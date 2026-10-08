package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

// Notifier delivers alert messages; batching, renotify and the digest stay in the hub.
type Notifier interface {
	Name() string
	Enabled() bool
	Send(Message) error
}

type Kind string

const (
	KindChange  Kind = "change"
	KindDigest  Kind = "digest"
	KindStartup Kind = "startup"
)

type Message struct {
	Kind          Kind
	Subject, Body string
	// Worst is the most severe new status in a change message.
	Worst status.Status
}

// send delivers to every enabled notifier; an error leaves the message due for the next pass.
func (h *Hub) send(m Message) error {
	var errs []error
	sent := false
	for _, n := range h.notifiers {
		if !n.Enabled() {
			continue
		}
		sent = true
		if err := n.Send(m); err != nil {
			slog.Error("notification failed", "via", n.Name(), "subject", m.Subject, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	if !sent {
		slog.Info("notifications disabled, not sending", "subject", m.Subject)
	}
	return errors.Join(errs...)
}

type change struct {
	id, name, msg string
	from, to      status.Status
}

// notify emails all due state changes in one message.
func (h *Hub) notify(now time.Time) {
	min := h.cfg.Alerts.RenotifyInterval.D()
	after := h.cfg.Alerts.UnknownAfter.D()
	// a never-run check has no Since, so also wait that long after startup
	stuckOK := after > 0 && now.Sub(h.started) >= after
	h.mu.Lock()
	var due []change
	for _, c := range h.checks {
		st := h.states[c.ID]
		stuck := stuckOK && st.StuckUnknown(now.Add(-after)) && !h.dependencyDown(c)
		if stuck || st.Due(now, min) {
			due = append(due, change{c.ID, c.Name, st.Message, st.Notified, st.Status})
		}
	}
	h.mu.Unlock()
	if len(due) == 0 {
		return
	}
	subject, body := ChangeMail(due)
	worst := status.OK
	for _, d := range due {
		worst = status.Worst(worst, d.to)
	}
	if err := h.send(Message{Kind: KindChange, Subject: subject, Body: body, Worst: worst}); err != nil {
		return // stays due; retried on the next pass
	}
	h.mu.Lock()
	for _, d := range due {
		h.states[d.id].MarkNotified(now)
	}
	h.mu.Unlock()
}

func label(s status.Status) string {
	if s == status.OK {
		return "OK"
	}
	return strings.ToUpper(s.String())
}

func ChangeMail(due []change) (string, string) {
	slices.SortFunc(due, func(a, b change) int { return b.to.Rank() - a.to.Rank() })
	var b strings.Builder
	counts := map[status.Status]int{}
	for _, d := range due {
		counts[d.to]++
		was := d.from.String()
		if !d.from.Alerting() {
			was = "new"
		}
		fmt.Fprintf(&b, "%-5s %s (was %s)\n      %s\n      %s\n\n", label(d.to), d.name, was, d.id, d.msg)
	}
	if len(due) == 1 {
		d := due[0]
		if d.to == status.OK {
			return "RECOVERED: " + d.name, b.String()
		}
		return label(d.to) + ": " + d.name, b.String()
	}
	var parts []string
	for _, s := range []status.Status{status.Crit, status.Warn, status.Unknown, status.OK} {
		if counts[s] > 0 {
			n := map[status.Status]string{status.Crit: "crit", status.Warn: "warn", status.Unknown: "unknown", status.OK: "recovered"}[s]
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], n))
		}
	}
	return fmt.Sprintf("%d changes: %s", len(due), strings.Join(parts, ", ")), b.String()
}

// dependencyDown is true when the check's agent isn't ok; that agent alerts instead. Caller holds h.mu.
func (h *Hub) dependencyDown(c *check.Check) bool {
	if c.DependsOn == "" {
		return false
	}
	d := h.states[c.DependsOn]
	return d == nil || d.Status != status.OK
}

// digestGrace keeps a digest from listing checks that haven't run since a restart.
const digestGrace = 10 * time.Minute

func (h *Hub) pastDigestTime(now time.Time) bool {
	hh, mm, _ := config.ParseClock(h.cfg.Alerts.DigestTime)
	return now.Hour()*60+now.Minute() >= hh*60+mm
}

// skipMissedDigest drops today's digest when starting after its time; the startup mail says enough.
func (h *Hub) skipMissedDigest(now time.Time) {
	h.started = now
	if h.cfg.Alerts.DigestTime != "" && h.pastDigestTime(now) {
		h.store.SetMeta("lastDigest", now.Format("2006-01-02"))
	}
}

// digest sends the daily summary once a day after alerts.digestTime.
func (h *Hub) digest(now time.Time) {
	if h.cfg.Alerts.DigestTime == "" {
		return
	}
	today := now.Format("2006-01-02")
	if !h.pastDigestTime(now) || h.store.Meta("lastDigest") == today || now.Sub(h.started) < digestGrace {
		return
	}
	var bad, locked []string
	okCount := 0
	h.mu.Lock()
	for _, c := range h.checks {
		st := h.states[c.ID]
		switch st.Status {
		case status.OK:
			okCount++
		case status.Locked:
			locked = append(locked, c.Name)
		default:
			bad = append(bad, fmt.Sprintf("%-7s %s since %s\n        %s", label(st.Status), c.Name,
				st.Since.Format("2006-01-02 15:04"), st.Message))
		}
	}
	h.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "%d checks ok, %d not ok, %d locked.\n\n", okCount, len(bad), len(locked))
	for _, l := range bad {
		b.WriteString(l + "\n")
	}
	if len(locked) > 0 {
		fmt.Fprintf(&b, "\nThe vault is locked; %d credentialed checks are not running. Run sitescope unlock on %s.\n", len(locked), h.cfg.Hub.Hostname)
	}
	subject := "daily digest: all ok"
	if len(bad) > 0 {
		subject = fmt.Sprintf("daily digest: %d not ok", len(bad))
	}
	if h.send(Message{Kind: KindDigest, Subject: subject, Body: b.String()}) == nil {
		h.store.SetMeta("lastDigest", today)
	}
}
