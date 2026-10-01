// Package alert holds per-check state: retries before a state change, and
// when a change is due for notification.
package alert

import (
	"time"

	"github.com/toppk/sitescope/internal/status"
)

type State struct {
	Status   status.Status `json:"status"`
	Since    time.Time     `json:"since"`
	Message  string        `json:"message"`
	LastRun  time.Time     `json:"lastRun"`
	TookMS   int64         `json:"tookMs"`
	Retrying int           `json:"retrying"`
	// Pending is the not-yet-committed status while retrying.
	Pending    status.Status `json:"pending"`
	Notified   status.Status `json:"notified"`
	NotifiedAt time.Time     `json:"notifiedAt"`
}

func bad(s status.Status) bool { return s == status.Warn || s == status.Crit }

// Observe applies a result. A move into warn/crit must repeat for retries
// further runs before it commits; recovery and unknown/locked commit at once.
// retry asks the scheduler to run the check again soon.
func (s *State) Observe(st status.Status, msg string, took time.Duration, retries int, now time.Time) (changed, retry bool) {
	s.LastRun, s.Message, s.TookMS = now, msg, took.Milliseconds()
	if st == s.Status {
		s.Retrying, s.Pending = 0, status.Unknown
		return false, false
	}
	if bad(st) && s.Retrying < retries {
		s.Retrying++
		s.Pending = st
		return false, true
	}
	s.Retrying, s.Pending = 0, status.Unknown
	s.Status, s.Since = st, now
	return true, false
}

// Due reports whether the committed status should be emailed now. Flapping
// is damped: after a notification, the next waits at least minInterval, and a
// check that flaps back to the notified status sends nothing.
func (s *State) Due(now time.Time, minInterval time.Duration) bool {
	if !s.Status.Alerting() || s.Status == s.Notified {
		return false
	}
	if !s.Notified.Alerting() && s.Status == status.OK {
		// first sight of a healthy check is not news
		s.Notified = status.OK
		return false
	}
	return s.NotifiedAt.IsZero() || now.Sub(s.NotifiedAt) >= minInterval
}

func (s *State) MarkNotified(now time.Time) status.Status {
	prev := s.Notified
	s.Notified, s.NotifiedAt = s.Status, now
	return prev
}
