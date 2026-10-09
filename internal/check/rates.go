package check

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/report"
)

// Rates are what changed between two agent reports, per second or as a share of the time.
type Rates struct {
	Span                      time.Duration
	CPUBusy, IOWait, Steal    float64 // percent of all CPUs
	PSISome, PSIFull          map[string]float64
	OOMKills                  uint64
	SwapIn, SwapOut, MajFault float64 // pages per second
	Disks                     []DiskRate
	Net                       []NetRate
}

type DiskRate struct {
	Device              string
	BusyPct             float64
	ReadBps, WriteBps   float64
	ReadIOPS, WriteIOPS float64
}

type NetRate struct {
	Device       string
	RxBps, TxBps float64
	ErrsPerSec   float64 // errors and drops, both directions
}

// sub is b-a for counters, 0 if the counter went backwards.
func sub(a, b uint64) float64 {
	if b < a {
		return 0
	}
	return float64(b - a)
}

func ComputeRates(a, b *report.Report) (Rates, error) {
	if a.Counters == nil || b.Counters == nil {
		return Rates{}, fmt.Errorf("agent reports no counters (older agent?)")
	}
	r := Rates{Span: b.Time.Sub(a.Time), PSISome: map[string]float64{}, PSIFull: map[string]float64{}}
	secs := r.Span.Seconds()
	if secs <= 0 {
		return r, fmt.Errorf("no time between reports")
	}
	ka, kb := a.Counters, b.Counters

	var total, idle, iowait, steal float64
	for i := range min(len(ka.CPU), len(kb.CPU)) {
		x, y := ka.CPU[i], kb.CPU[i]
		d := func(f func(report.CPU) float64) float64 { return max(f(y)-f(x), 0) }
		idle += d(func(c report.CPU) float64 { return c.Idle })
		iowait += d(func(c report.CPU) float64 { return c.IOWait })
		steal += d(func(c report.CPU) float64 { return c.Steal })
		total += d(func(c report.CPU) float64 {
			return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
		})
	}
	if total > 0 {
		r.CPUBusy = 100 * (total - idle - iowait) / total
		r.IOWait, r.Steal = 100*iowait/total, 100*steal/total
	}
	for res, pb := range kb.Pressure {
		pa := ka.Pressure[res]
		r.PSISome[res] = 100 * sub(pa.SomeTotalUS, pb.SomeTotalUS) / 1e6 / secs
		r.PSIFull[res] = 100 * sub(pa.FullTotalUS, pb.FullTotalUS) / 1e6 / secs
	}
	r.OOMKills = uint64(sub(ka.VM.OOMKill, kb.VM.OOMKill))
	r.SwapIn = sub(ka.VM.PswpIn, kb.VM.PswpIn) / secs
	r.SwapOut = sub(ka.VM.PswpOut, kb.VM.PswpOut) / secs
	r.MajFault = sub(ka.VM.PgMajFault, kb.VM.PgMajFault) / secs

	for _, y := range kb.Disks {
		i := slices.IndexFunc(ka.Disks, func(x report.DiskIO) bool { return x.Device == y.Device })
		if i < 0 {
			continue
		}
		x := ka.Disks[i]
		r.Disks = append(r.Disks, DiskRate{Device: y.Device,
			BusyPct: min(100, 100*sub(x.IOTimeMS, y.IOTimeMS)/1000/secs),
			ReadBps: sub(x.ReadBytes, y.ReadBytes) / secs, WriteBps: sub(x.WrittenBytes, y.WrittenBytes) / secs,
			ReadIOPS: sub(x.Reads, y.Reads) / secs, WriteIOPS: sub(x.Writes, y.Writes) / secs})
	}
	for _, y := range kb.Net {
		i := slices.IndexFunc(ka.Net, func(x report.NetIO) bool { return x.Device == y.Device })
		if i < 0 {
			continue
		}
		x := ka.Net[i]
		errs := sub(x.RxErrs, y.RxErrs) + sub(x.TxErrs, y.TxErrs) + sub(x.RxDrop, y.RxDrop) + sub(x.TxDrop, y.TxDrop)
		r.Net = append(r.Net, NetRate{Device: y.Device, RxBps: sub(x.RxBytes, y.RxBytes) / secs,
			TxBps: sub(x.TxBytes, y.TxBytes) / secs, ErrsPerSec: errs / secs})
	}
	return r, nil
}

// maxListed caps how many devices a message names, busiest first.
const maxListed = 4

func over(span time.Duration) string { return "over " + fmtDuration(span.Round(time.Second)) }

func EvalCPU(r Rates, busy Threshold) Result {
	msg := fmt.Sprintf("%.0f%% busy %s (iowait %.0f%%, steal %.0f%%", r.CPUBusy, over(r.Span), r.IOWait, r.Steal)
	if p, ok := r.PSISome["cpu"]; ok {
		msg += fmt.Sprintf(", tasks waited %.1f%% of the time", p)
	}
	return Rated(busy.Above(r.CPUBusy), "%s)", msg)
}

// EvalMemPressure looks past usage at what memory shortage costs: stalls, swap-in, OOM kills.
func EvalMemPressure(r Rates, stall, swapIn Threshold) Result {
	some, ok := r.PSISome["memory"]
	if !ok {
		return Unknownf("no /proc/pressure on this kernel")
	}
	s := Worst(stall.Above(some), swapIn.Above(r.SwapIn))
	msg := fmt.Sprintf("stalled %.1f%% of the time (all tasks %.1f%%), swap in %.0f/s out %.0f pages/s, %.0f major faults/s, %s",
		some, r.PSIFull["memory"], r.SwapIn, r.SwapOut, r.MajFault, over(r.Span))
	if r.OOMKills > 0 {
		return Critf("%d OOM kill(s); %s", r.OOMKills, msg)
	}
	return Rated(s, "%s", msg)
}

func EvalDiskIO(r Rates, busy, pressure Threshold) Result {
	if len(r.Disks) == 0 {
		return Unknownf("no disks reported")
	}
	s := pressure.Above(r.PSISome["io"])
	ds := slices.Clone(r.Disks)
	slices.SortStableFunc(ds, func(a, b DiskRate) int { return cmp.Compare(b.BusyPct, a.BusyPct) })
	var parts []string
	for i, d := range ds {
		s = Worst(s, busy.Above(d.BusyPct))
		if i < maxListed && (i == 0 || d.BusyPct >= 1) {
			parts = append(parts, fmt.Sprintf("%s %.0f%% busy, read %s/s, write %s/s", d.Device, d.BusyPct,
				fmtBytes(d.ReadBps), fmtBytes(d.WriteBps)))
		}
	}
	return Rated(s, "%s; tasks stalled on I/O %.1f%% of the time %s", strings.Join(parts, "; "), r.PSISome["io"], over(r.Span))
}

func EvalNetwork(r Rates, errs, mbps Threshold) Result {
	if len(r.Net) == 0 {
		return Unknownf("no interfaces reported")
	}
	s := OK
	ns := slices.Clone(r.Net)
	slices.SortStableFunc(ns, func(a, b NetRate) int { return cmp.Compare(b.RxBps+b.TxBps, a.RxBps+a.TxBps) })
	var parts []string
	for i, n := range ns {
		in, out := n.RxBps*8/1e6, n.TxBps*8/1e6
		s = Worst(s, errs.Above(n.ErrsPerSec), mbps.Above(max(in, out)))
		if i >= maxListed && n.ErrsPerSec == 0 {
			continue
		}
		p := fmt.Sprintf("%s in %.2f out %.2f Mbit/s", n.Device, in, out)
		if n.ErrsPerSec > 0 {
			p += fmt.Sprintf(", %.1f errors+drops/s", n.ErrsPerSec)
		}
		parts = append(parts, p)
	}
	return Rated(s, "%s %s", strings.Join(parts, "; "), over(r.Span))
}

// EvalUnitMemory rates services against their MemoryMax.
func EvalUnitMemory(r *report.Report, t Threshold) Result {
	if r.Units == nil {
		return Unknownf("no cgroup memory reported")
	}
	var limited []report.UnitMem
	for _, u := range r.Units {
		if u.MaxBytes > 0 {
			limited = append(limited, u)
		}
	}
	if len(limited) == 0 {
		return Okf("no services have a MemoryMax")
	}
	pct := func(u report.UnitMem) float64 { return 100 * float64(u.Bytes) / float64(u.MaxBytes) }
	slices.SortFunc(limited, func(a, b report.UnitMem) int { return cmp.Compare(pct(b), pct(a)) })
	s := OK
	var parts []string
	for i, u := range limited {
		s = Worst(s, t.Above(pct(u)))
		if i < 3 || t.Above(pct(u)) != OK {
			parts = append(parts, fmt.Sprintf("%s %s of %s (%.0f%%)", strings.TrimSuffix(u.Unit, ".service"),
				fmtBytes(float64(u.Bytes)), fmtBytes(float64(u.MaxBytes)), pct(u)))
		}
	}
	return Rated(s, "%s", strings.Join(parts, ", "))
}

// topUnits names the services using the most memory.
func topUnits(r *report.Report, n int) string {
	us := slices.Clone(r.Units)
	slices.SortFunc(us, func(a, b report.UnitMem) int { return cmp.Compare(b.Bytes, a.Bytes) })
	var parts []string
	for _, u := range us[:min(n, len(us))] {
		parts = append(parts, strings.TrimSuffix(u.Unit, ".service")+" "+fmtBytes(float64(u.Bytes)))
	}
	return strings.Join(parts, ", ")
}

func fmtBytes(b float64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TiB", b/(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KiB", b/(1<<10))
	}
	return fmt.Sprintf("%.0f B", b)
}
