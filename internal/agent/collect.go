// Package agent collects local host facts and serves them to the hub.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

const cmdTimeout = 5 * time.Second

// collectTimeout bounds each collector, even one stuck in a syscall such as statfs on a hung mount.
var collectTimeout = 8 * time.Second

// Collector gathers a report; the root is overridable for tests.
type Collector struct {
	Cfg  config.Agent
	Root string
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

// collector fills one report section; applies is nil when it always runs.
type collector struct {
	name    string
	applies func(c *Collector) bool
	run     func(c *Collector, ctx context.Context, r *report.Report) error
}

func plain(f func(c *Collector, r *report.Report) error) func(*Collector, context.Context, *report.Report) error {
	return func(c *Collector, _ context.Context, r *report.Report) error { return f(c, r) }
}

var collectors = []collector{
	{"os", nil, plain((*Collector).osRelease)},
	{"uptime", nil, plain((*Collector).uptime)},
	{"load", nil, plain((*Collector).load)},
	{"memory", nil, plain((*Collector).memory)},
	{"disks", nil, plain((*Collector).disks)},
	{"system", (*Collector).isNixOS, plain((*Collector).system)},
	{"kernel", func(c *Collector) bool { return !c.isNixOS() }, plain((*Collector).kernel)},
	{"packages", func(c *Collector) bool { return !c.isNixOS() }, plain((*Collector).packages)},
	{"units", nil, (*Collector).failedUnits},
	{"counters", nil, plain((*Collector).counters)},
	{"cgroups", nil, plain((*Collector).units)},
	{"wireguard", func(c *Collector) bool { return c.Cfg.WireGuardOn() }, (*Collector).wireguard},
	{"postfix", func(c *Collector) bool { return c.Cfg.Postfix }, (*Collector).postfix},
	{"knot", func(c *Collector) bool { return c.Cfg.Knot }, (*Collector).knot},
}

// Collect runs the collectors in parallel, each into its own report, and merges what finished in time.
func (c *Collector) Collect(ctx context.Context) *report.Report {
	r := &report.Report{Time: time.Now().UTC(), CPUs: runtime.NumCPU(), Errors: map[string]string{}}
	r.Host, _ = os.Hostname()
	type done struct {
		name string
		part *report.Report
		err  error
	}
	ch := make(chan done, len(collectors))
	pending := map[string]bool{}
	for _, k := range collectors {
		if k.applies != nil && !k.applies(c) {
			continue
		}
		pending[k.name] = true
		go func() {
			part := &report.Report{}
			err := k.run(c, ctx, part)
			ch <- done{k.name, part, err}
		}()
	}
	timeout := time.After(collectTimeout)
	for len(pending) > 0 {
		select {
		case d := <-ch:
			delete(pending, d.name)
			if d.err != nil {
				r.Errors[d.name] = d.err.Error()
			}
			merge(r, d.part)
		case <-timeout:
			// a stuck collector keeps its own report, so leaving it behind is safe
			for name := range pending {
				r.Errors[name] = fmt.Sprintf("timed out after %s", collectTimeout)
			}
			pending = nil
		}
	}
	if len(r.Errors) == 0 {
		r.Errors = nil
	}
	return r
}

// merge copies the fields a collector set; collectors fill disjoint fields.
func merge(dst, src *report.Report) {
	d, s := reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem()
	for i := range s.NumField() {
		if f := s.Field(i); !f.IsZero() {
			d.Field(i).Set(f)
		}
	}
}

// isNixOS is decided per collection; /run/current-system appears before services start.
func (c *Collector) isNixOS() bool {
	_, err := os.Lstat(c.path("/run/current-system"))
	return err == nil
}

func (c *Collector) osRelease(r *report.Report) error {
	b, err := os.ReadFile(c.path("/etc/os-release"))
	if err != nil {
		return err
	}
	o := &report.OS{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.VersionID = v
		case "PRETTY_NAME":
			o.Name = v
		}
	}
	r.OS = o
	return nil
}

func (c *Collector) uptime(r *report.Report) error {
	b, err := os.ReadFile(c.path("/proc/uptime"))
	if err != nil {
		return err
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return fmt.Errorf("bad /proc/uptime")
	}
	r.UptimeSec, err = strconv.ParseFloat(f[0], 64)
	return err
}

func (c *Collector) load(r *report.Report) error {
	b, err := os.ReadFile(c.path("/proc/loadavg"))
	if err != nil {
		return err
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return fmt.Errorf("bad /proc/loadavg")
	}
	for i := range 3 {
		if r.Load[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) memory(r *report.Report) error {
	b, err := os.ReadFile(c.path("/proc/meminfo"))
	if err != nil {
		return err
	}
	m := &r.Memory
	fields := map[string]*uint64{
		"MemTotal": &m.TotalKB, "MemAvailable": &m.AvailableKB, "MemFree": &m.FreeKB, "Buffers": &m.BuffersKB,
		"Cached": &m.CachedKB, "Shmem": &m.ShmemKB, "Dirty": &m.DirtyKB,
		"SwapTotal": &m.SwapTotalKB, "SwapFree": &m.SwapFreeKB,
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if p := fields[k]; ok && p != nil {
			f := strings.Fields(v)
			if len(f) > 0 {
				*p, _ = strconv.ParseUint(f[0], 10, 64)
			}
		}
	}
	if r.Memory.TotalKB == 0 {
		return fmt.Errorf("MemTotal missing")
	}
	return nil
}

var diskFS = map[string]bool{"ext4": true, "ext3": true, "xfs": true, "btrfs": true, "vfat": true, "zfs": true, "f2fs": true}

func (c *Collector) disks(r *report.Report) error {
	b, err := os.ReadFile(c.path("/proc/self/mountinfo"))
	if err != nil {
		return err
	}
	// one entry per device: bind mounts (PrivateTmp, ProtectSystem) repeat the same filesystem
	seen := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 1 || !diskFS[qf[0]] {
			continue
		}
		dev, mount := pf[2], unescapeMount(pf[4])
		if i, ok := seen[dev]; ok {
			if len(mount) < len(r.Disks[i].Mount) {
				r.Disks[i].Mount = mount
			}
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(c.path(mount), &st); err != nil {
			continue
		}
		d := report.Disk{Mount: mount, FSType: qf[0], TotalBytes: st.Blocks * uint64(st.Bsize),
			AvailBytes: st.Bavail * uint64(st.Bsize), Files: st.Files, FilesFree: st.Ffree}
		if len(qf) > 1 {
			d.Device = qf[1]
		}
		if used := st.Blocks - st.Bfree; used+st.Bavail > 0 {
			d.UsedPct = round1(100 * float64(used) / float64(used+st.Bavail))
		}
		if st.Files > 0 {
			d.InodesPct = round1(100 * float64(st.Files-st.Ffree) / float64(st.Files))
		}
		seen[dev] = len(r.Disks)
		r.Disks = append(r.Disks, d)
	}
	return nil
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

var nixVersionDate = regexp.MustCompile(`\.(\d{8})\.`)

func (c *Collector) system(r *report.Report) error {
	booted, err1 := os.Readlink(c.path("/run/booted-system"))
	current, err2 := os.Readlink(c.path("/run/current-system"))
	if err1 != nil || err2 != nil {
		return fmt.Errorf("not a NixOS system: %v %v", err1, err2)
	}
	r.System.Booted, r.System.Current = booted, current
	// nixos-rebuild's own notion: only kernel, initrd and modules require a reboot
	for _, p := range []string{"kernel", "initrd", "kernel-modules"} {
		a, _ := os.Readlink(c.path(filepath.Join("/run/booted-system", p)))
		b, _ := os.Readlink(c.path(filepath.Join("/run/current-system", p)))
		if a != b {
			r.System.RebootNeeded = true
		}
	}
	v, err := os.ReadFile(c.path("/run/current-system/nixos-version"))
	if err != nil {
		return err
	}
	r.System.NixosVersion = strings.TrimSpace(string(v))
	if m := nixVersionDate.FindStringSubmatch(r.System.NixosVersion + "."); m != nil {
		r.System.NixpkgsDate = m[1]
	}
	return nil
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (c *Collector) failedUnits(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, c.Cfg.Systemctl, "list-units", "--state=failed", "--all", "--output=json", "--no-pager")
	if err != nil {
		return err
	}
	var units []struct {
		Unit string `json:"unit"`
	}
	if err := json.Unmarshal(out, &units); err != nil {
		return err
	}
	r.FailedUnits = []string{}
	for _, u := range units {
		r.FailedUnits = append(r.FailedUnits, u.Unit)
	}
	return nil
}

func (c *Collector) wireguard(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, c.Cfg.WG, "show", c.Cfg.WGInterface, "latest-handshakes")
	if err != nil {
		return err
	}
	if r.WireGuard, err = ParseHandshakes(out); err != nil {
		return err
	}
	// transfer, not dump: dump prints the interface's private key
	out, err = run(ctx, c.Cfg.WG, "show", c.Cfg.WGInterface, "transfer")
	if err != nil {
		return err
	}
	tr := ParseTransfer(out)
	for i, p := range r.WireGuard {
		r.WireGuard[i].RxBytes, r.WireGuard[i].TxBytes = tr[p.PublicKey][0], tr[p.PublicKey][1]
	}
	return nil
}

func ParseHandshakes(out []byte) ([]report.WGPeer, error) {
	peers := []report.WGPeer{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		t, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wg: bad handshake time %q", f[1])
		}
		peers = append(peers, report.WGPeer{PublicKey: f[0], LatestHandshake: t})
	}
	return peers, nil
}

func (c *Collector) postfix(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, c.Cfg.Postqueue, "-j")
	if err != nil {
		return err
	}
	r.Postfix, err = ParsePostqueue(out, time.Now())
	return err
}

// ParsePostqueue reads `postqueue -j` output (one JSON object per message).
func ParsePostqueue(out []byte, now time.Time) (*report.Postfix, error) {
	p := &report.Postfix{Queues: map[string]int{}}
	oldest := int64(0)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m struct {
			Queue       string `json:"queue_name"`
			ArrivalTime int64  `json:"arrival_time"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("postqueue: %w", err)
		}
		p.Messages++
		p.Queues[m.Queue]++
		if oldest == 0 || m.ArrivalTime < oldest {
			oldest = m.ArrivalTime
		}
	}
	if oldest > 0 {
		p.OldestAgeSec = now.Sub(time.Unix(oldest, 0)).Seconds()
	}
	return p, sc.Err()
}

func (c *Collector) knot(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, c.Cfg.Knotc, "-s", c.Cfg.KnotSocket, "zone-status")
	if err != nil {
		return err
	}
	r.Knot = ParseKnotStatus(out)
	return nil
}

var knotLine = regexp.MustCompile(`^\[([^\]]+)\]\s*(.*)$`)

// ParseKnotStatus reads `knotc zone-status` lines like
// "[example.org.] role: slave | serial: 2026100101 | ... | expiration: +27D23h59m".
func ParseKnotStatus(out []byte) []report.Zone {
	zones := []report.Zone{}
	for _, line := range strings.Split(string(out), "\n") {
		m := knotLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		z := report.Zone{Name: strings.TrimSuffix(m[1], "."), ExpiresInSec: -1}
		for _, kv := range strings.Split(m[2], "|") {
			k, v, _ := strings.Cut(strings.TrimSpace(kv), ":")
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "role":
				z.Role = v
			case "serial":
				s, _ := strconv.ParseUint(v, 10, 32)
				z.Serial = uint32(s)
			case "expiration":
				if d, ok := parseKnotDuration(v); ok {
					z.ExpiresInSec = d
				}
			}
		}
		zones = append(zones, z)
	}
	return zones
}

var knotDur = regexp.MustCompile(`^([+-])((?:\d+[YMDhms])+)$`)
var knotDurPart = regexp.MustCompile(`(\d+)([YMDhms])`)

func parseKnotDuration(s string) (int64, bool) {
	m := knotDur.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	unit := map[string]int64{"Y": 365 * 86400, "M": 30 * 86400, "D": 86400, "h": 3600, "m": 60, "s": 1}
	var total int64
	for _, p := range knotDurPart.FindAllStringSubmatch(m[2], -1) {
		n, _ := strconv.ParseInt(p[1], 10, 64)
		total += n * unit[p[2]]
	}
	if m[1] == "-" {
		total = -total
	}
	return total, true
}
