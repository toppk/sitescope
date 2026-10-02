package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/toppk/sitescope/internal/report"
)

// userHZ is the kernel's clock tick for /proc/stat; 100 on every Linux we run.
const userHZ = 100

func (c *Collector) counters(r *report.Report) error {
	k := &report.Counters{}
	r.Counters = k
	var errs []string
	note := func(what string, err error) {
		if err != nil {
			errs = append(errs, what+": "+err.Error())
		}
	}
	note("stat", c.stat(k))
	note("vmstat", c.vmstat(k))
	note("diskstats", c.diskstats(k))
	note("net", c.netdev(k))
	for _, res := range []string{"cpu", "memory", "io"} {
		p, err := c.pressure(res)
		if err != nil {
			note("pressure", err)
			break
		}
		if k.Pressure == nil {
			k.Pressure = map[string]report.PSI{}
		}
		k.Pressure[res] = p
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func lines(b []byte) []string { return strings.Split(strings.TrimSpace(string(b)), "\n") }

func (c *Collector) stat(k *report.Counters) error {
	b, err := os.ReadFile(c.path("/proc/stat"))
	if err != nil {
		return err
	}
	k.CPU, k.BootTime, err = ParseStat(b)
	return err
}

// ParseStat reads per-CPU times (seconds) and the boot time from /proc/stat.
func ParseStat(b []byte) ([]report.CPU, int64, error) {
	var cpus []report.CPU
	var boot int64
	for _, l := range lines(b) {
		f := strings.Fields(l)
		switch {
		case len(f) >= 9 && strings.HasPrefix(f[0], "cpu") && f[0] != "cpu":
			v := make([]float64, 8)
			for i := range v {
				n, _ := strconv.ParseUint(f[i+1], 10, 64)
				v[i] = float64(n) / userHZ
			}
			cpus = append(cpus, report.CPU{User: v[0], Nice: v[1], System: v[2], Idle: v[3],
				IOWait: v[4], IRQ: v[5], SoftIRQ: v[6], Steal: v[7]})
		case len(f) == 2 && f[0] == "btime":
			boot, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if len(cpus) == 0 {
		return nil, 0, fmt.Errorf("no cpu lines")
	}
	return cpus, boot, nil
}

func (c *Collector) vmstat(k *report.Counters) error {
	b, err := os.ReadFile(c.path("/proc/vmstat"))
	if err != nil {
		return err
	}
	fields := map[string]*uint64{"oom_kill": &k.VM.OOMKill, "pswpin": &k.VM.PswpIn,
		"pswpout": &k.VM.PswpOut, "pgmajfault": &k.VM.PgMajFault}
	for _, l := range lines(b) {
		name, v, _ := strings.Cut(l, " ")
		if p := fields[name]; p != nil {
			*p, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return nil
}

// skipDisk drops partitions and virtual devices, as node_exporter does.
var skipDisk = regexp.MustCompile(`^(z?ram|loop|fd|(h|s|v|xv)d[a-z]+|nvme\d+n\d+p)\d+$`)

func (c *Collector) diskstats(k *report.Counters) error {
	b, err := os.ReadFile(c.path("/proc/diskstats"))
	if err != nil {
		return err
	}
	k.Disks = ParseDiskstats(b)
	return nil
}

func ParseDiskstats(b []byte) []report.DiskIO {
	out := []report.DiskIO{}
	for _, l := range lines(b) {
		f := strings.Fields(l)
		if len(f) < 14 || skipDisk.MatchString(f[2]) {
			continue
		}
		n := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out = append(out, report.DiskIO{Device: f[2], Reads: n(3), ReadBytes: n(5) * 512,
			Writes: n(7), WrittenBytes: n(9) * 512, IOTimeMS: n(12)})
	}
	return out
}

func (c *Collector) netdev(k *report.Counters) error {
	b, err := os.ReadFile(c.path("/proc/net/dev"))
	if err != nil {
		return err
	}
	k.Net = ParseNetDev(b)
	return nil
}

func ParseNetDev(b []byte) []report.NetIO {
	out := []report.NetIO{}
	for _, l := range lines(b) {
		name, rest, ok := strings.Cut(l, ":")
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if !ok || len(f) < 16 || name == "lo" || strings.HasPrefix(name, "veth") {
			continue
		}
		n := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out = append(out, report.NetIO{Device: name, RxBytes: n(0), RxErrs: n(2), RxDrop: n(3),
			TxBytes: n(8), TxErrs: n(10), TxDrop: n(11)})
	}
	return out
}

func (c *Collector) pressure(res string) (report.PSI, error) {
	b, err := os.ReadFile(c.path("/proc/pressure/" + res))
	if err != nil {
		return report.PSI{}, err
	}
	return ParsePSI(b), nil
}

// ParsePSI reads "some avg10=0.00 avg60=0.00 avg300=0.00 total=123" lines.
func ParsePSI(b []byte) report.PSI {
	var p report.PSI
	for _, l := range lines(b) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		var avg60 float64
		var total uint64
		for _, kv := range f[1:] {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "avg60":
				avg60, _ = strconv.ParseFloat(v, 64)
			case "total":
				total, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		switch f[0] {
		case "some":
			p.SomeAvg60, p.SomeTotalUS = avg60, total
		case "full":
			p.FullAvg60, p.FullTotalUS = avg60, total
		}
	}
	return p
}

// units reads each system service's cgroup memory use and limit.
func (c *Collector) units(r *report.Report) error {
	dirs, err := filepath.Glob(c.path("/sys/fs/cgroup/system.slice/*.service"))
	if err != nil {
		return err
	}
	if len(dirs) == 0 {
		return fmt.Errorf("no service cgroups under /sys/fs/cgroup/system.slice")
	}
	r.Units = []report.UnitMem{}
	for _, d := range dirs {
		cur, err := readUint(filepath.Join(d, "memory.current"))
		if err != nil {
			continue
		}
		u := report.UnitMem{Unit: filepath.Base(d), Bytes: cur}
		u.MaxBytes, _ = readUint(filepath.Join(d, "memory.max")) // "max" means unlimited
		r.Units = append(r.Units, u)
	}
	return nil
}

func readUint(p string) (uint64, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(bytes.TrimSpace(b)), 10, 64)
}

// ParseTransfer reads `wg show IFACE transfer`: key, received bytes, sent bytes.
func ParseTransfer(out []byte) map[string][2]uint64 {
	m := map[string][2]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		rx, _ := strconv.ParseUint(f[1], 10, 64)
		tx, _ := strconv.ParseUint(f[2], 10, 64)
		m[f[0]] = [2]uint64{rx, tx}
	}
	return m
}
