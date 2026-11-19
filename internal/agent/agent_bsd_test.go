//go:build freebsd || openbsd

package agent

import (
	"context"
	"runtime"
	"slices"
	"testing"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

// TestCollectBSD runs the real collectors on this machine.
func TestCollectBSD(t *testing.T) {
	c := &Collector{Cfg: config.Agent{WireGuard: new(bool)}}
	r := c.Collect(context.Background())
	for k, v := range r.Errors {
		t.Errorf("collector %s: %s", k, v)
	}
	if r.OS == nil || r.OS.ID != runtime.GOOS {
		t.Errorf("os = %+v", r.OS)
	}
	if r.UptimeSec <= 0 || r.Load[0] < 0 || r.CPUs < 1 {
		t.Errorf("uptime %v, load %v, cpus %d", r.UptimeSec, r.Load, r.CPUs)
	}
	if m := r.Memory; m.TotalKB == 0 || m.AvailableKB == 0 || m.AvailableKB > m.TotalKB || m.SwapFreeKB > m.SwapTotalKB {
		t.Errorf("memory = %+v", m)
	}
	if !slices.ContainsFunc(r.Disks, func(d report.Disk) bool { return d.Mount == "/" && d.TotalBytes > 0 }) {
		t.Errorf("disks lack /: %+v", r.Disks)
	}
	if r.Counters == nil || len(r.Counters.CPU) == 0 || r.Counters.CPU[0].Idle <= 0 || r.Counters.BootTime == 0 {
		t.Errorf("counters = %+v", r.Counters)
	}
	if r.Packages == nil || r.Packages.Changed == 0 {
		t.Errorf("packages = %+v", r.Packages)
	}
	switch runtime.GOOS {
	case "freebsd":
		if r.Kernel == nil || r.Kernel.Running == "" || r.Kernel.Newest == "" {
			t.Errorf("kernel = %+v", r.Kernel)
		}
	case "openbsd":
		if r.FailedUnits == nil {
			t.Error("failed services weren't listed")
		}
	}
	t.Logf("%s: load %v, mem %d/%d KB, swap %d/%d KB, %d disks, %d CPUs counted, %d nics, failed %v, kernel %+v, packages %+v",
		r.OS.Name, r.Load, r.Memory.AvailableKB, r.Memory.TotalKB, r.Memory.SwapFreeKB, r.Memory.SwapTotalKB,
		len(r.Disks), len(r.Counters.CPU), len(r.Counters.Net), r.FailedUnits, r.Kernel, r.Packages)
}

func TestUnitsBSD(t *testing.T) {
	c := &Collector{}
	q := UnitQuery{System: []string{"sshd", "nosuchd"}}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := c.Units(context.Background(), q)
	if err != nil || len(st) != 2 {
		t.Fatalf("units = %+v, %v", st, err)
	}
	if st[0].Load != "loaded" || st[0].Active != "active" {
		t.Errorf("sshd = %+v", st[0])
	}
	if st[1].Load != "not-found" {
		t.Errorf("nosuchd = %+v", st[1])
	}
	for _, bad := range []UnitQuery{{System: []string{"sshd.service"}}, {User: []string{"x"}}} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}
