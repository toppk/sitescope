package alert

import (
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/status"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }

func TestRetriesBeforeFailing(t *testing.T) {
	s := &State{}
	s.Observe(status.OK, "fine", 0, 2, at(0))
	if c, r := s.Observe(status.Crit, "down", 0, 2, at(1)); c || !r {
		t.Fatalf("first failure: changed=%v retry=%v", c, r)
	}
	if c, r := s.Observe(status.Crit, "down", 0, 2, at(2)); c || !r {
		t.Fatalf("second failure: changed=%v retry=%v", c, r)
	}
	if s.Status != status.OK || s.Retrying != 2 || s.Pending != status.Crit {
		t.Fatalf("state while retrying: %+v", s)
	}
	if c, r := s.Observe(status.Crit, "down", 0, 2, at(3)); !c || r {
		t.Fatalf("third failure: changed=%v retry=%v", c, r)
	}
	if s.Status != status.Crit || !s.Since.Equal(at(3)) || s.Retrying != 0 {
		t.Fatalf("committed state: %+v", s)
	}
}

func TestTransientFailureNeverCommits(t *testing.T) {
	s := &State{}
	s.Observe(status.OK, "", 0, 2, at(0))
	s.Observe(status.Warn, "", 0, 2, at(1))
	if c, _ := s.Observe(status.OK, "", 0, 2, at(2)); c {
		t.Fatal("recovery during retry should not count as a change")
	}
	if s.Retrying != 0 {
		t.Fatal("retry counter not reset")
	}
	if c, r := s.Observe(status.Warn, "", 0, 2, at(3)); c || !r {
		t.Fatal("a new failure must start retrying from zero")
	}
}

func TestRecoveryAndLockedCommitImmediately(t *testing.T) {
	s := &State{Status: status.Crit}
	if c, _ := s.Observe(status.OK, "", 0, 5, at(0)); !c {
		t.Fatal("recovery should commit immediately")
	}
	if c, _ := s.Observe(status.Locked, "", 0, 5, at(1)); !c || s.Status != status.Locked {
		t.Fatal("locked should commit immediately")
	}
}

func TestZeroRetries(t *testing.T) {
	s := &State{Status: status.OK}
	if c, r := s.Observe(status.Crit, "", 0, 0, at(0)); !c || r {
		t.Fatal("with zero retries a failure commits at once")
	}
}

func TestDueInitialOKIsSilent(t *testing.T) {
	s := &State{}
	s.Observe(status.OK, "", 0, 0, at(0))
	if s.Due(at(0), time.Hour) {
		t.Fatal("initial ok should not notify")
	}
	if s.Notified != status.OK {
		t.Fatal("initial ok should be recorded as notified")
	}
}

func TestDueInitialFailureNotifies(t *testing.T) {
	s := &State{}
	s.Observe(status.Crit, "", 0, 0, at(0))
	if !s.Due(at(0), time.Hour) {
		t.Fatal("initial crit should notify")
	}
}

func TestDedupeAndRenotifyInterval(t *testing.T) {
	s := &State{}
	s.Observe(status.OK, "", 0, 0, at(0))
	s.Due(at(0), time.Hour)

	s.Observe(status.Crit, "", 0, 0, at(1))
	if !s.Due(at(1), time.Hour) {
		t.Fatal("ok->crit should notify")
	}
	s.MarkNotified(at(1))
	if s.Due(at(2), time.Hour) {
		t.Fatal("same status must not notify twice")
	}

	// flap: recovery 5 minutes later is held back by the interval
	s.Observe(status.OK, "", 0, 0, at(6))
	if s.Due(at(6), time.Hour) {
		t.Fatal("recovery within renotify interval should wait")
	}
	// flaps back to crit before the interval passes: nothing to send at all
	s.Observe(status.Crit, "", 0, 0, at(20))
	if s.Due(at(70), time.Hour) {
		t.Fatal("status equal to the notified one must not notify")
	}
	// stays recovered past the interval: now it goes out
	s.Observe(status.OK, "", 0, 0, at(80))
	if !s.Due(at(80), time.Hour) {
		t.Fatal("recovery after the interval should notify")
	}
	if prev := s.MarkNotified(at(80)); prev != status.Crit {
		t.Fatalf("previous notified = %v", prev)
	}
}

func TestUnknownAndLockedDoNotNotify(t *testing.T) {
	s := &State{Status: status.Crit, Notified: status.Crit, NotifiedAt: at(0)}
	s.Observe(status.Unknown, "", 0, 0, at(100))
	if s.Due(at(100), time.Minute) {
		t.Fatal("unknown should not notify")
	}
	s.Observe(status.Locked, "", 0, 0, at(101))
	if s.Due(at(101), time.Minute) {
		t.Fatal("locked should not notify")
	}
	s.Observe(status.OK, "", 0, 0, at(102))
	if !s.Due(at(102), time.Minute) {
		t.Fatal("recovery from crit (via unknown) should notify")
	}
}

func TestStuckUnknown(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var s State
	if s.StuckUnknown(t0) {
		t.Fatal("a check waiting for its first run isn't stuck")
	}
	s.Observe(status.Unknown, "RDAP: timeout", 0, 2, t0)
	if !s.StuckUnknown(t0.Add(time.Hour)) {
		t.Fatal("a check that ran and couldn't decide is stuck")
	}
	s.MarkNotified(t0.Add(time.Hour))
	if s.StuckUnknown(t0.Add(2 * time.Hour)) {
		t.Fatal("reported once only")
	}
	s.Observe(status.OK, "fine", 0, 2, t0.Add(3*time.Hour))
	if !s.Due(t0.Add(3*time.Hour), time.Hour) {
		t.Fatal("recovery after an unknown alert is news")
	}
}
