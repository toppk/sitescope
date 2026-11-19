//go:build freebsd || openbsd

package agent

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/report"
)

// Supported is whether the agent has collectors for this system.
const Supported = true

var collectors = []collector{
	{"os", nil, plain((*Collector).osRelease)},
	{"uptime", nil, plain((*Collector).bsdUptime)},
	{"load", nil, plain((*Collector).bsdLoad)},
	{"memory", nil, (*Collector).bsdMemory},
	{"disks", nil, plain((*Collector).bsdDisks)},
	{"kernel", func(*Collector) bool { return kernelFacts }, (*Collector).bsdKernel},
	{"packages", nil, plain((*Collector).packages)},
	{"units", func(*Collector) bool { return failedServices }, (*Collector).failedServices},
	{"counters", nil, (*Collector).bsdCounters},
	{"wireguard", func(c *Collector) bool { return c.Cfg.WireGuardOn() }, (*Collector).wireguard},
	{"postfix", func(c *Collector) bool { return c.Cfg.Postfix }, (*Collector).postfix},
	{"knot", func(c *Collector) bool { return c.Cfg.Knot }, (*Collector).knot},
}

// rc service names: no systemd suffixes, and no user managers.
var unitName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

const userUnits = false

var systemdSuffix = regexp.MustCompile(`\.(service|timer|socket|mount|path|target)$`)

func validUnit(name string) bool {
	return unitName.MatchString(name) && !systemdSuffix.MatchString(name)
}

// freebind does nothing: the BSDs have no IP_FREEBIND, so the agent starts after wg0 has its address.
func freebind(int) error { return nil }

type fsStat struct{ blocks, bfree, bavail, bsize, files, ffree uint64 }

func statfs(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	e := toEntry(&st)
	return e.fsStat, nil
}

type fsEntry struct {
	fsStat
	mount, from, fstype string
}

func (c *Collector) bsdUptime(r *report.Report) error {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return err
	}
	r.UptimeSec = time.Since(time.Unix(tv.Sec, int64(tv.Usec)*1000)).Seconds()
	return nil
}

func (c *Collector) bsdLoad(r *report.Report) error {
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return err
	}
	r.Load, err = ParseLoadavg(b)
	return err
}

// bsdDiskFS are filesystems on disks; devfs, tmpfs, nullfs and the like are left out.
var bsdDiskFS = map[string]bool{"ufs": true, "zfs": true, "ffs": true, "msdosfs": true, "msdos": true, "ext2fs": true}

func (c *Collector) bsdDisks(r *report.Report) error {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return err
	}
	buf := make([]unix.Statfs_t, n)
	if n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT); err != nil {
		return err
	}
	seen := map[string]bool{}
	r.Disks = []report.Disk{}
	for i := range buf[:n] {
		e := toEntry(&buf[i])
		if !bsdDiskFS[e.fstype] || seen[e.from] {
			continue
		}
		seen[e.from] = true
		d := report.Disk{Device: e.from, Mount: e.mount, FSType: e.fstype, TotalBytes: e.blocks * e.bsize,
			AvailBytes: e.bavail * e.bsize, Files: e.files, FilesFree: e.ffree}
		if used := e.blocks - e.bfree; used+e.bavail > 0 {
			d.UsedPct = round1(100 * float64(used) / float64(used+e.bavail))
		}
		if e.files > 0 {
			d.InodesPct = round1(100 * float64(e.files-e.ffree) / float64(e.files))
		}
		r.Disks = append(r.Disks, d)
	}
	return nil
}

func (c *Collector) bsdCounters(ctx context.Context, r *report.Report) error {
	k := &report.Counters{}
	r.Counters = k
	var errs []string
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		k.BootTime = tv.Sec
	} else {
		errs = append(errs, "boottime: "+err.Error())
	}
	var err error
	if k.CPU, err = cpuTimes(); err != nil {
		errs = append(errs, "cpu: "+err.Error())
	}
	if k.Net, err = netCounters(ctx); err != nil {
		errs = append(errs, "net: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func stathz() (int, error) {
	ci, err := unix.SysctlClockinfo("kern.clockrate")
	if err != nil {
		return 0, err
	}
	return int(ci.Stathz), nil
}

// Units reports the queried rc services' state.
func (c *Collector) Units(ctx context.Context, q UnitQuery) ([]report.UnitState, error) {
	out := []report.UnitState{}
	for _, name := range q.System {
		out = append(out, serviceState(ctx, name))
	}
	return out, nil
}
