package hub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"slices"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

type Mailer struct {
	cfg  config.Alerts
	host string
	url  string
}

func (m *Mailer) Enabled() bool { return m.cfg.Enabled && len(m.cfg.To) > 0 }

// Send submits to the local MTA without TLS or auth: it is loopback and postfix signs with DKIM.
func (m *Mailer) Send(subject, body string) error {
	if !m.Enabled() {
		slog.Info("mail disabled, not sending", "subject", subject)
		return nil
	}
	err := m.send(subject, body)
	if err != nil {
		slog.Error("sending mail failed", "subject", subject, "err", err)
	}
	return err
}

func (m *Mailer) send(subject, body string) error {
	conn, err := net.DialTimeout("tcp", m.cfg.SMTP, 10*time.Second)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	host, _, _ := net.SplitHostPort(m.cfg.SMTP)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(m.host); err != nil {
		return err
	}
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	for _, to := range m.cfg.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(m.message(subject, body, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m *Mailer) message(subject, body string, now time.Time) []byte {
	id := make([]byte, 12)
	rand.Read(id)
	domain := m.cfg.From[strings.LastIndex(m.cfg.From, "@")+1:]
	var b strings.Builder
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", "sitescope <"+m.cfg.From+">")
	hdr("To", strings.Join(m.cfg.To, ", "))
	hdr("Subject", strings.TrimSpace(m.cfg.SubjectPrefix+" "+subject))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	hdr("Auto-Submitted", "auto-generated")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	if m.url != "" {
		b.WriteString("\r\n-- \r\n" + strings.TrimSuffix(m.url, "/") + "/detail\r\n")
	}
	return []byte(b.String())
}

type change struct {
	id, name, msg string
	from, to      status.Status
}

// notify emails all due state changes in one message.
func (h *Hub) notify(now time.Time) {
	min := h.cfg.Alerts.RenotifyInterval.D()
	h.mu.Lock()
	var due []change
	for _, c := range h.checks {
		st := h.states[c.ID]
		if st.Due(now, min) {
			due = append(due, change{c.ID, c.Name, st.Message, st.Notified, st.Status})
		}
	}
	h.mu.Unlock()
	if len(due) == 0 {
		return
	}
	subject, body := ChangeMail(due)
	if err := h.mailer.Send(subject, body); err != nil {
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
	for _, s := range []status.Status{status.Crit, status.Warn, status.OK} {
		if counts[s] > 0 {
			n := map[status.Status]string{status.Crit: "crit", status.Warn: "warn", status.OK: "recovered"}[s]
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], n))
		}
	}
	return fmt.Sprintf("%d changes: %s", len(due), strings.Join(parts, ", ")), b.String()
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
	if h.mailer.Send(subject, b.String()) == nil {
		h.store.SetMeta("lastDigest", today)
	}
}
