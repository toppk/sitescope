package check

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/agent"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

// Unit is a systemd unit that must be active; a timer must also be scheduled and its last run must have succeeded.
type Unit struct {
	Name string `json:"name"`
	// User units are asked of the agent user's own systemd manager.
	User bool `json:"user,omitempty"`
	// Severity is crit (the default) or warn.
	Severity string `json:"severity,omitempty"`
	// MaxAge is how recent a timer's last run must be; unset, only an overdue run counts.
	MaxAge config.Duration `json:"maxAge,omitempty"`
}

func (u Unit) severity() Status {
	if u.Severity == "warn" {
		return Warn
	}
	return Crit
}

func (u Unit) validate(host string) error {
	if !strings.Contains(u.Name, ".") {
		return fmt.Errorf("hosts: %s unit %q needs its suffix, e.g. %s.service", host, u.Name, u.Name)
	}
	if u.Severity != "" && u.Severity != "warn" && u.Severity != "crit" {
		return fmt.Errorf("hosts: %s unit %s severity %q, want warn or crit", host, u.Name, u.Severity)
	}
	return nil
}

func unitQuery(units []Unit) agent.UnitQuery {
	var q agent.UnitQuery
	for _, u := range units {
		if u.User {
			q.User = append(q.User, u.Name)
		} else {
			q.System = append(q.System, u.Name)
		}
	}
	return q
}

// urlQuery is appended to the agent's report URL.
func urlQuery(q agent.UnitQuery) string {
	if q.Empty() {
		return ""
	}
	return "?" + url.Values{"unit": q.System, "userUnit": q.User}.Encode()
}

// overdue is how late a timer may run before it counts as missed.
const overdue = time.Hour

func EvalUnit(r *report.Report, now time.Time, u Unit) Result {
	if r.Services == nil {
		return Unknownf("the agent does not report unit state; it needs sitescope 1.4.0 or later")
	}
	var s *report.UnitState
	for i := range r.Services {
		if r.Services[i].Unit == u.Name && r.Services[i].User == u.User {
			s = &r.Services[i]
		}
	}
	if s == nil {
		return Unknownf("not in the agent's report")
	}
	bad := func(f string, a ...any) Result { return Rated(u.severity(), f, a...) }
	if s.Load != "loaded" {
		return bad("%s: %s", s.Unit, s.Load)
	}
	if !strings.HasSuffix(u.Name, ".timer") {
		if s.Active != "active" {
			return bad("%s (%s)", s.Active, s.Sub)
		}
		return Okf("active (%s)", s.Sub)
	}
	at := func(t int64) time.Time { return time.Unix(t, 0) }
	next := "not scheduled"
	if s.NextRun > 0 {
		next = "next in " + fmtDuration(at(s.NextRun).Sub(now))
	}
	if s.Active != "active" {
		return bad("timer %s, %s", s.Active, next)
	}
	if s.LastRun == 0 {
		if s.NextRun == 0 {
			return bad("never run and not scheduled")
		}
		return Okf("not run yet, %s", next)
	}
	ago := now.Sub(at(s.LastRun))
	last := fmt.Sprintf("last run %s ago", fmtDuration(ago))
	if s.Running {
		last += ", running now"
	} else if s.Result != "" && s.Result != "success" {
		return bad("%s failed: %s, exit status %d; %s", last, s.Result, s.ExitStatus, next)
	}
	if u.MaxAge > 0 && ago > u.MaxAge.D() {
		return bad("%s, over %s; %s", last, fmtDuration(u.MaxAge.D()), next)
	}
	if s.NextRun == 0 {
		return bad("%s, not scheduled again", last)
	}
	if late := now.Sub(at(s.NextRun)); late > overdue {
		return bad("%s, overdue by %s", last, fmtDuration(late))
	}
	return Okf("%s, %s", last, next)
}
