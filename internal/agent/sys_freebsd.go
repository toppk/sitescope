package agent

import (
	"context"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/report"
)

// FreeBSD's rc keeps no failed state, so there's no failed-services collector.
const kernelFacts, failedServices = true, false

func toEntry(st *unix.Statfs_t) fsEntry {
	return fsEntry{
		fsStat: fsStat{st.Blocks, st.Bfree, uint64(max(st.Bavail, 0)), st.Bsize, st.Files, uint64(max(st.Ffree, 0))},
		mount:  unix.ByteSliceToString(st.Mntonname[:]), from: unix.ByteSliceToString(st.Mntfromname[:]),
		fstype: unix.ByteSliceToString(st.Fstypename[:]),
	}
}

// bsdMemory counts free and inactive pages as available; laundry pages are dirty and not counted.
func (c *Collector) bsdMemory(ctx context.Context, r *report.Report) error {
	total, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		return err
	}
	ps, err := unix.SysctlUint32("hw.pagesize")
	if err != nil {
		return err
	}
	free, err1 := unix.SysctlUint32("vm.stats.vm.v_free_count")
	inactive, err2 := unix.SysctlUint32("vm.stats.vm.v_inactive_count")
	if err1 != nil || err2 != nil {
		return firstErr(err1, err2)
	}
	kb := func(pages uint32) uint64 { return uint64(pages) * uint64(ps) / 1024 }
	m := &r.Memory
	m.TotalKB, m.FreeKB, m.CachedKB, m.AvailableKB = total/1024, kb(free), kb(inactive), kb(free)+kb(inactive)
	out, err := run(ctx, "/usr/sbin/swapinfo", "-k")
	if err != nil {
		return err
	}
	t, u, err := ParseSwapinfo(out)
	m.SwapTotalKB, m.SwapFreeKB = t, t-u
	return err
}

// bsdKernel compares the installed kernel (freebsd-version -k) with the running one (-r).
func (c *Collector) bsdKernel(ctx context.Context, r *report.Report) error {
	k, err := run(ctx, "/bin/freebsd-version", "-k")
	if err != nil {
		return err
	}
	running, err := run(ctx, "/bin/freebsd-version", "-r")
	if err != nil {
		return err
	}
	r.Kernel = &report.Kernel{Running: strings.TrimSpace(string(running)), Newest: strings.TrimSpace(string(k))}
	return nil
}

func (c *Collector) failedServices(context.Context, *report.Report) error { return nil }

func cpuTimes() ([]report.CPU, error) {
	hz, err := stathz()
	if err != nil {
		return nil, err
	}
	b, err := unix.SysctlRaw("kern.cp_times")
	if err != nil {
		return nil, err
	}
	return CPUTicks(b, 5, hz)
}

func netCounters(ctx context.Context) ([]report.NetIO, error) {
	out, err := run(ctx, "/usr/bin/netstat", "-ibn", "--libxo", "json")
	if err != nil {
		return nil, err
	}
	return ParseNetstatJSON(out)
}

// serviceState runs `service NAME status`. A root-only pid file, as for cron and syslogd,
// leaves it unreadable to the agent's user, so then a process of that exact name answers.
func serviceState(ctx context.Context, name string) report.UnitState {
	out, err := run(ctx, "/usr/sbin/service", name, "status")
	if err != nil && strings.Contains(string(out)+err.Error(), "Permission denied") {
		s := report.UnitState{Unit: name, Load: "loaded", Active: "active", Sub: "running, by process name"}
		if _, perr := run(ctx, "/bin/pgrep", "-x", name); perr != nil {
			s.Active, s.Sub = "inactive", "no process "+name+" (its pid file is root-only)"
		}
		return s
	}
	return ServiceState("freebsd", name, out, err)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
