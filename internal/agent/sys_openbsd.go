package agent

import (
	"context"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/report"
)

// OpenBSD relinks /bsd at every boot and keeps it root-only, so there's no kernel collector.
const kernelFacts, failedServices = false, true

func toEntry(st *unix.Statfs_t) fsEntry {
	return fsEntry{
		fsStat: fsStat{st.F_blocks, st.F_bfree, uint64(max(st.F_bavail, 0)), uint64(st.F_bsize), st.F_files, st.F_ffree},
		mount:  unix.ByteSliceToString(st.F_mntonname[:]), from: unix.ByteSliceToString(st.F_mntfromname[:]),
		fstype: unix.ByteSliceToString(st.F_fstypename[:]),
	}
}

func (c *Collector) bsdMemory(_ context.Context, r *report.Report) error {
	total, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		return err
	}
	u, err := unix.SysctlUvmexp("vm.uvmexp")
	if err != nil {
		return err
	}
	kb := func(pages int32) uint64 { return uint64(max(pages, 0)) * uint64(u.Pagesize) / 1024 }
	m := &r.Memory
	m.TotalKB, m.FreeKB, m.CachedKB, m.AvailableKB = total/1024, kb(u.Free), kb(u.Inactive), kb(u.Free)+kb(u.Inactive)
	m.SwapTotalKB, m.SwapFreeKB = kb(u.Swpages), kb(u.Swpages-u.Swpginuse)
	return nil
}

func (c *Collector) bsdKernel(context.Context, *report.Report) error { return nil }

// failedServices lists enabled daemons that aren't running, as `rcctl ls failed` would, which needs root.
func (c *Collector) failedServices(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, "/usr/sbin/rcctl", "ls", "on")
	if err != nil {
		return err
	}
	r.FailedUnits = []string{}
	for _, name := range strings.Fields(string(out)) {
		if s := serviceState(ctx, name); s.Load == "loaded" && s.Active != "active" {
			r.FailedUnits = append(r.FailedUnits, name)
		}
	}
	return nil
}

func cpuTimes() ([]report.CPU, error) {
	hz, err := stathz()
	if err != nil {
		return nil, err
	}
	b, err := unix.SysctlRaw("kern.cp_time")
	if err != nil {
		return nil, err
	}
	return CPUTicks(b, 6, hz)
}

func netCounters(ctx context.Context) ([]report.NetIO, error) {
	b, err := run(ctx, "/usr/bin/netstat", "-ibn")
	if err != nil {
		return nil, err
	}
	p, err := run(ctx, "/usr/bin/netstat", "-in")
	if err != nil {
		return nil, err
	}
	return ParseNetstatOpenBSD(b, p), nil
}

func serviceState(ctx context.Context, name string) report.UnitState {
	out, err := run(ctx, "/usr/sbin/rcctl", "check", name)
	return ServiceState("openbsd", name, out, err)
}
