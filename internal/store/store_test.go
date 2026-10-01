package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/status"
)

func TestHistoryPruneAndState(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	st := &alert.State{Status: status.Warn}
	for i := range 40 {
		e := Entry{Time: t0.AddDate(0, 0, i), Status: status.OK, Message: "day"}
		if err := s.Record("a", e, st); err != nil {
			t.Fatal(err)
		}
	}
	s.Record("gone", Entry{Time: t0, Status: status.Crit}, st)

	if err := s.Prune(t0.AddDate(0, 0, 10), map[string]bool{"a": true}); err != nil {
		t.Fatal(err)
	}
	h, _ := s.History("a", time.Time{}, 0)
	if len(h) != 30 {
		t.Fatalf("kept %d entries, want 30", len(h))
	}
	if !h[0].Time.After(h[1].Time) {
		t.Fatal("history not newest first")
	}
	if h, _ := s.History("gone", time.Time{}, 0); len(h) != 0 {
		t.Fatal("unconfigured check history not pruned")
	}
	states, _ := s.States()
	if len(states) != 1 || states["a"].Status != status.Warn {
		t.Fatalf("states = %v", states)
	}
	if last, ok := s.Last("a"); !ok || !last.Time.Equal(t0.AddDate(0, 0, 39)) {
		t.Fatalf("last = %v", last.Time)
	}
}

func TestDailyWorst(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	es := []Entry{
		{Time: now.Add(-1 * time.Hour), Status: status.OK},
		{Time: now.Add(-2 * time.Hour), Status: status.Crit},
		{Time: now.Add(-25 * time.Hour), Status: status.Warn},
	}
	d := DailyWorst(es, 3, now)
	if d[0] != status.Locked || d[1] != status.Warn || d[2] != status.Crit {
		t.Fatalf("daily = %v", d)
	}
}
