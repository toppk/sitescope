package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

type Hosts struct {
	config.Timing
	Hosts       []Host            `json:"hosts"`
	WGPeers     map[string]string `json:"wgPeers"`
	Disk        Threshold         `json:"disk"`
	Memory      Threshold         `json:"memory"`
	Swap        Threshold         `json:"swap"`
	Load        Threshold         `json:"load"`
	WGHandshake Threshold         `json:"wgHandshake"`
	QueueSize   Threshold         `json:"queueSize"`
	QueueAge    Threshold         `json:"queueAge"`
	KnotExpiry  Threshold         `json:"knotExpiry"`
	NixpkgsAge  Threshold         `json:"nixpkgsAge"`
	// Rates are computed over RateWindow from the agents' counters.
	RateWindow  config.Duration `json:"rateWindow"`
	CPU         Threshold       `json:"cpu"`         // percent busy
	MemoryStall Threshold       `json:"memoryStall"` // percent of time some task waited on memory
	SwapIn      Threshold       `json:"swapIn"`      // pages per second
	DiskBusy    Threshold       `json:"diskBusy"`    // percent of time a device was busy
	IOStall     Threshold       `json:"ioStall"`     // percent of time some task waited on I/O
	NetErrors   Threshold       `json:"netErrors"`   // errors and drops per second
	NetMbps     Threshold       `json:"netMbps"`     // off unless set
	UnitMemory  Threshold       `json:"unitMemory"`  // percent of a service's MemoryMax
	KnotZones   []string        `json:"knotZones"`
}

type Host struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Postfix bool   `json:"postfix"`
	Knot    bool   `json:"knot"`
	// OS is "nixos" (the default) or another os-release ID; the NixOS checks need nixos.
	OS string `json:"os,omitempty"`
	// WireGuard is on unless set to false.
	WireGuard *bool `json:"wireguard,omitempty"`
	// CA is a PEM file that verifies an https agent URL, e.g. the private CA.
	CA string `json:"ca,omitempty"`
	// TokenEnv names the variable holding this agent's token (default SITESCOPE_AGENT_TOKEN).
	TokenEnv string `json:"tokenEnv,omitempty"`
	// WireGuard peers to ignore (by name or key), e.g. a roaming peer that may sleep.
	WGIgnore []string `json:"wgIgnore"`
}

func (hs *Hosts) Defaults(*config.Config) {
	hs.Disk = hs.Disk.Or(Threshold{Warn: 80, Crit: 90})
	hs.Memory = hs.Memory.Or(Threshold{Warn: 90, Crit: 97})
	hs.Swap = hs.Swap.Or(Threshold{Warn: 60, Crit: 90})
	hs.Load = hs.Load.Or(Threshold{Warn: 2, Crit: 4})
	hs.WGHandshake = hs.WGHandshake.Or(Threshold{Warn: 600, Crit: 3600})
	hs.QueueSize = hs.QueueSize.Or(Threshold{Warn: 20, Crit: 200})
	hs.QueueAge = hs.QueueAge.Or(Threshold{Warn: 3600, Crit: 4 * 3600})
	hs.KnotExpiry = hs.KnotExpiry.Or(Threshold{Warn: 14 * 86400, Crit: 3 * 86400})
	hs.NixpkgsAge = hs.NixpkgsAge.Or(Threshold{Warn: 30, Crit: 90})
	if hs.RateWindow == 0 {
		hs.RateWindow = config.Duration(5 * time.Minute)
	}
	hs.CPU = hs.CPU.Or(Threshold{Warn: 85, Crit: 95})
	hs.MemoryStall = hs.MemoryStall.Or(Threshold{Warn: 10, Crit: 30})
	hs.SwapIn = hs.SwapIn.Or(Threshold{Warn: 100, Crit: 1000})
	hs.DiskBusy = hs.DiskBusy.Or(Threshold{Warn: 80, Crit: 95})
	hs.IOStall = hs.IOStall.Or(Threshold{Warn: 25, Crit: 50})
	hs.NetErrors = hs.NetErrors.Or(Threshold{Warn: 1, Crit: 10})
	hs.UnitMemory = hs.UnitMemory.Or(Threshold{Warn: 85, Crit: 95})
}

func (hs *Hosts) Validate() error { return nil }

func (hs *Hosts) build(b *builder) {
	t := hs.Timing.Merge(config.Timing{Interval: config.Duration(time.Minute), Timeout: config.Duration(10 * time.Second)})
	interval := t.Merge(b.cfg.Defaults).Interval.D()
	stale := max(3*interval, 5*time.Minute)
	// derived checks re-read the cached report, so they never retry on their own
	derived := t
	derived.Retries = new(int)
	knotZones := hs.KnotZones
	if d := config.Get[*DNS](b.cfg); len(knotZones) == 0 && d != nil {
		knotZones = d.Zones
	}
	for _, h := range hs.Hosts {
		agentID := "host." + h.Name + ".agent"
		b.add(t, &Check{ID: agentID, Name: h.Name + " agent reachable", Area: "hosts", Group: h.Name,
			Probes: []Probe{urlProbe(h.URL, "GET /v1/report with the agent token")}, Run: agentCheck(h)})
		d := func(id, name, area, section string, eval func(*report.Report, time.Time) Result) {
			b.add(derived, &Check{ID: "host." + h.Name + "." + id, Name: h.Name + " " + name, Area: area, Group: h.Name,
				DependsOn: agentID, Run: fromReport(h.Name, section, stale, eval)})
		}
		d("disk", "disk usage", "hosts", "disks", func(r *report.Report, _ time.Time) Result { return EvalDisk(r, hs.Disk) })
		d("memory", "memory", "hosts", "memory", func(r *report.Report, _ time.Time) Result { return EvalMemory(r, hs.Memory) })
		d("swap", "swap", "hosts", "memory", func(r *report.Report, _ time.Time) Result { return EvalSwap(r, hs.Swap) })
		d("load", "load average", "hosts", "load", func(r *report.Report, _ time.Time) Result { return EvalLoad(r, hs.Load) })
		d("units", "failed systemd units", "hosts", "units", func(r *report.Report, _ time.Time) Result { return EvalUnits(r) })
		d("cgroups", "unit memory", "hosts", "cgroups", func(r *report.Report, _ time.Time) Result { return EvalUnitMemory(r, hs.UnitMemory) })
		w := func(id, name string, eval func(Rates) Result) {
			b.add(derived, &Check{ID: "host." + h.Name + "." + id, Name: h.Name + " " + name, Area: "hosts", Group: h.Name,
				DependsOn: agentID, Run: fromWindow(h.Name, stale, hs.RateWindow.D(), eval)})
		}
		w("cpu", "CPU", func(r Rates) Result { return EvalCPU(r, hs.CPU) })
		w("pressure", "memory pressure", func(r Rates) Result { return EvalMemPressure(r, hs.MemoryStall, hs.SwapIn) })
		w("diskio", "disk I/O", func(r Rates) Result { return EvalDiskIO(r, hs.DiskBusy, hs.IOStall) })
		w("network", "network", func(r Rates) Result { return EvalNetwork(r, hs.NetErrors, hs.NetMbps) })
		if h.WireGuard == nil || *h.WireGuard {
			d("wireguard", "WireGuard handshakes", "hosts", "wireguard", func(r *report.Report, now time.Time) Result {
				return EvalWireGuard(r, now, hs.WGHandshake, hs.WGPeers, h.WGIgnore)
			})
		}
		if h.OS == "" || h.OS == "nixos" {
			d("reboot", "reboot needed", "hygiene", "system", func(r *report.Report, _ time.Time) Result { return EvalReboot(r) })
			d("nixpkgs", "nixpkgs age", "hygiene", "system", func(r *report.Report, now time.Time) Result {
				return EvalNixpkgs(r, now, hs.NixpkgsAge)
			})
		}
		if h.Postfix {
			d("postfix", "mail queue", "mail", "postfix", func(r *report.Report, _ time.Time) Result {
				return EvalQueue(r, hs.QueueSize, hs.QueueAge)
			})
		}
		if h.Knot {
			d("knot", "Knot zones", "dns", "knot", func(r *report.Report, _ time.Time) Result {
				return EvalKnot(r, hs.KnotExpiry, knotZones)
			})
		}
	}
}

func agentCheck(h Host) func(context.Context, *Env) Result {
	var mu sync.Mutex
	var client *http.Client
	return func(ctx context.Context, env *Env) Result {
		c := env.HTTP
		if h.CA != "" {
			mu.Lock()
			if client == nil {
				var err error
				if client, err = CAClient(h.CA); err != nil {
					mu.Unlock()
					return Critf("agent CA: %v", err)
				}
			}
			c = client
			mu.Unlock()
		}
		token := env.AgentToken
		if h.TokenEnv != "" {
			token = os.Getenv(h.TokenEnv)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(h.URL, "/")+"/v1/report", nil)
		if err != nil {
			return Critf("%v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.Do(req)
		if err != nil {
			return Critf("agent unreachable: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return Critf("agent returned %s", resp.Status)
		}
		var r report.Report
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
			return Critf("bad report: %v", err)
		}
		env.Reports.Put(h.Name, &r, env.now())
		return Okf("up %s", fmtDuration(time.Duration(r.UptimeSec)*time.Second))
	}
}

// CAClient trusts only the CA in file, for agents and hubs with private-CA certificates.
func CAClient(file string) (*http.Client, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", file)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: time.Minute, Transport: tr}, nil
}

// fromWindow rates the counters between the latest report and one a window earlier.
func fromWindow(host string, stale, window time.Duration, eval func(Rates) Result) func(context.Context, *Env) Result {
	return func(_ context.Context, env *Env) Result {
		cur, at := env.Reports.Get(host)
		if cur == nil {
			return Unknownf("no report from agent yet")
		}
		if age := env.now().Sub(at); age > stale {
			return Unknownf("last report %s ago", fmtDuration(age))
		}
		if e := cur.Errors["counters"]; e != "" {
			return Warnf("agent could not collect counters: %s", e)
		}
		old, cur := env.Reports.Window(host, window)
		if span := cur.Time.Sub(old.Time); span < min(window, 2*time.Minute) {
			return Unknownf("collecting a baseline (%s of %s)", fmtDuration(span), fmtDuration(window))
		}
		r, err := ComputeRates(old, cur)
		if err != nil {
			return Unknownf("%v", err)
		}
		return eval(r)
	}
}

func fromReport(host, section string, stale time.Duration, eval func(*report.Report, time.Time) Result) func(context.Context, *Env) Result {
	return func(_ context.Context, env *Env) Result {
		r, at := env.Reports.Get(host)
		now := env.now()
		if r == nil {
			return Unknownf("no report from agent yet")
		}
		if now.Sub(at) > stale {
			return Unknownf("last report %s ago", fmtDuration(now.Sub(at)))
		}
		if e := r.Errors[section]; e != "" {
			return Warnf("agent could not collect %s: %s", section, e)
		}
		return eval(r, now)
	}
}

func EvalDisk(r *report.Report, t Threshold) Result {
	if len(r.Disks) == 0 {
		return Unknownf("no filesystems reported")
	}
	worst, parts := OK, []string{}
	for _, d := range r.Disks {
		s := Worst(t.Above(d.UsedPct), t.Above(d.InodesPct))
		worst = Worst(worst, s)
		parts = append(parts, fmt.Sprintf("%s %.0f%%", d.Mount, d.UsedPct))
		if d.InodesPct >= t.Warn && t.Warn > 0 {
			parts[len(parts)-1] += fmt.Sprintf(" (inodes %.0f%%)", d.InodesPct)
		}
	}
	return Rated(worst, "%s", strings.Join(parts, ", "))
}

func EvalMemory(r *report.Report, t Threshold) Result {
	m := r.Memory
	if m.TotalKB == 0 {
		return Unknownf("no memory info")
	}
	used := 100 * (1 - float64(m.AvailableKB)/float64(m.TotalKB))
	msg := fmt.Sprintf("%.0f%% used: %s available of %s (page cache %s, not counted)", used,
		fmtBytes(float64(m.AvailableKB)*1024), fmtBytes(float64(m.TotalKB)*1024), fmtBytes(float64(m.CachedKB+m.BuffersKB)*1024))
	if len(r.Units) > 0 {
		msg += "; largest: " + topUnits(r, 3)
	}
	return Rated(t.Above(used), "%s", msg)
}

func EvalSwap(r *report.Report, t Threshold) Result {
	m := r.Memory
	if m.SwapTotalKB == 0 {
		return Okf("no swap")
	}
	used := 100 * (1 - float64(m.SwapFreeKB)/float64(m.SwapTotalKB))
	return Rated(t.Above(used), "%.0f%% used of %d MB", used, m.SwapTotalKB/1024)
}

// EvalLoad rates the 5-minute load per CPU.
func EvalLoad(r *report.Report, t Threshold) Result {
	cpus := max(r.CPUs, 1)
	per := r.Load[1] / float64(cpus)
	return Rated(t.Above(per), "load %.2f %.2f %.2f on %d CPU", r.Load[0], r.Load[1], r.Load[2], cpus)
}

func EvalUnits(r *report.Report) Result {
	if len(r.FailedUnits) == 0 {
		return Okf("none failed")
	}
	return Warnf("failed: %s", strings.Join(r.FailedUnits, ", "))
}

func EvalReboot(r *report.Report) Result {
	if r.System.RebootNeeded {
		return Warnf("kernel or initrd changed since boot")
	}
	if r.System.Booted != r.System.Current {
		return Okf("running a newer generation, no reboot needed")
	}
	return Okf("booted generation is current")
}

func EvalNixpkgs(r *report.Report, now time.Time, t Threshold) Result {
	d, err := time.Parse("20060102", r.System.NixpkgsDate)
	if err != nil {
		return Unknownf("no nixpkgs date in version %q", r.System.NixosVersion)
	}
	days := now.Sub(d).Hours() / 24
	return Rated(t.Above(days), "nixpkgs from %s (%.0f days, %s)", d.Format("2006-01-02"), days, r.System.NixosVersion)
}

func EvalWireGuard(r *report.Report, now time.Time, t Threshold, names map[string]string, ignore []string) Result {
	if len(r.WireGuard) == 0 {
		return Critf("no WireGuard peers")
	}
	worst, parts := OK, []string{}
	for _, p := range r.WireGuard {
		name := names[p.PublicKey]
		if name == "" {
			name = p.PublicKey[:min(8, len(p.PublicKey))]
		}
		if slices.Contains(ignore, name) || slices.Contains(ignore, p.PublicKey) {
			continue
		}
		if p.LatestHandshake == 0 {
			worst = Crit
			parts = append(parts, name+" never")
			continue
		}
		age := now.Sub(time.Unix(p.LatestHandshake, 0))
		worst = Worst(worst, t.Above(age.Seconds()))
		parts = append(parts, fmt.Sprintf("%s %s ago", name, fmtDuration(age)))
	}
	return Rated(worst, "%s", strings.Join(parts, ", "))
}

func EvalQueue(r *report.Report, size, age Threshold) Result {
	q := r.Postfix
	if q == nil {
		return Unknownf("no postfix data")
	}
	s := Worst(size.Above(float64(q.Messages)), age.Above(q.OldestAgeSec))
	if q.Messages == 0 {
		return Rated(s, "queue empty")
	}
	return Rated(s, "%d queued, oldest %s", q.Messages, fmtDuration(time.Duration(q.OldestAgeSec)*time.Second))
}

func EvalKnot(r *report.Report, expiry Threshold, want []string) Result {
	worst, bad := OK, []string{}
	have := map[string]bool{}
	for _, z := range r.Knot {
		have[fqdn(z.Name)] = true
		switch {
		case z.Serial == 0:
			worst = Crit
			bad = append(bad, z.Name+" not loaded")
		case z.ExpiresInSec >= 0:
			if s := expiry.Below(float64(z.ExpiresInSec)); s != OK {
				worst = Worst(worst, s)
				bad = append(bad, fmt.Sprintf("%s expires in %s", z.Name, fmtDuration(time.Duration(z.ExpiresInSec)*time.Second)))
			}
		}
	}
	for _, w := range want {
		if !have[fqdn(w)] {
			worst = Crit
			bad = append(bad, fqdn(w)+" missing")
		}
	}
	if len(bad) == 0 {
		return Okf("%d zones loaded", len(r.Knot))
	}
	return Rated(worst, "%s", strings.Join(bad, ", "))
}

func fmtDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "-" + fmtDuration(-d)
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
