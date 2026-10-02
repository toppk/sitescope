package hub

import (
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/status"
)

func TestGrid(t *testing.T) {
	boot := time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC)
	g := grid{boot: boot, tick: time.Minute}
	if got := g.at(boot.Add(61 * time.Second)); got != boot.Add(2*time.Minute) {
		t.Errorf("at rounds up to the grid: %s", got)
	}
	if got := g.at(boot.Add(30 * time.Second)); got != boot.Add(time.Minute) {
		t.Errorf("a 30s retry waits for the next step: %s", got)
	}
	a := boot.Add(3 * time.Minute)
	if got := g.after(a, 5*time.Minute, a.Add(2*time.Second)); got != a.Add(5*time.Minute) {
		t.Errorf("after keeps the phase: %s", got)
	}
	if got := g.after(a, 5*time.Minute, a.Add(17*time.Minute)); got != a.Add(20*time.Minute) {
		t.Errorf("after skips missed slots: %s", got)
	}
}

func TestPhasesAndPlan(t *testing.T) {
	var checks []*check.Check
	for _, d := range []string{"a", "b", "c", "d"} {
		checks = append(checks, &check.Check{ID: "ct." + d, Interval: 24 * time.Hour, Spread: "certspotter"})
	}
	checks = append(checks,
		&check.Check{ID: "host.x.agent", Interval: time.Minute},
		&check.Check{ID: "dns.soa.z", Interval: 5 * time.Minute},
		&check.Check{ID: "tls.z", Interval: 6 * time.Hour})
	ph := phases(checks, time.Minute)
	for i, id := range []string{"ct.a", "ct.b", "ct.c", "ct.d"} {
		if ph[id] != time.Duration(i)*6*time.Hour {
			t.Errorf("%s phase %s, want spread evenly over the day", id, ph[id])
		}
	}
	if ph["host.x.agent"] != 0 || ph["dns.soa.z"] >= 5*time.Minute || ph["tls.z"] >= spreadWindow || ph["tls.z"]%time.Minute != 0 {
		t.Errorf("phases = %v", ph)
	}

	boot := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g := grid{boot: boot, tick: time.Minute}
	states := map[string]*alert.State{
		"ct.b":  {Status: status.OK, LastRun: boot.Add(-time.Hour)},       // ran an hour ago: resumes a day after
		"tls.z": {Status: status.Locked, LastRun: boot.Add(-time.Minute)}, // locked: runs on its phase
	}
	an := plan(checks, states, g)
	if an["ct.b"] != boot.Add(23*time.Hour) {
		t.Errorf("a restart keeps a checked domain's pace: %s", an["ct.b"])
	}
	if an["ct.c"] != boot.Add(12*time.Hour) || an["host.x.agent"] != boot {
		t.Errorf("plan = %v", an)
	}
	if an["tls.z"] != boot.Add(ph["tls.z"]) {
		t.Errorf("locked checks don't resume: %s", an["tls.z"])
	}
}
