package agent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/toppk/sitescope/internal/report"
)

// ParseSwapinfo sums the devices in FreeBSD's `swapinfo -k`: 1K-blocks and used.
func ParseSwapinfo(out []byte) (totalKB, usedKB uint64, err error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] == "Device" || f[0] == "Total" {
			continue
		}
		t, err1 := strconv.ParseUint(f[1], 10, 64)
		u, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("swapinfo: bad line %q", sc.Text())
		}
		totalKB += t
		usedKB += u
	}
	return totalKB, usedKB, nil
}

// ParseNetstatJSON reads FreeBSD's `netstat -ibn --libxo json`: one link-level row per interface.
func ParseNetstatJSON(out []byte) ([]report.NetIO, error) {
	var doc struct {
		Statistics struct {
			Interface []struct {
				Name    string `json:"name"`
				Network string `json:"network"`
				RxBytes uint64 `json:"received-bytes"`
				TxBytes uint64 `json:"sent-bytes"`
				RxErrs  uint64 `json:"received-errors"`
				TxErrs  uint64 `json:"send-errors"`
				RxDrop  uint64 `json:"dropped-packets"`
			} `json:"interface"`
		} `json:"statistics"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	nets := []report.NetIO{}
	for _, i := range doc.Statistics.Interface {
		if strings.HasPrefix(i.Network, "<Link") && !strings.HasPrefix(i.Name, "lo") {
			nets = append(nets, report.NetIO{Device: i.Name, RxBytes: i.RxBytes, TxBytes: i.TxBytes, RxErrs: i.RxErrs, TxErrs: i.TxErrs, RxDrop: i.RxDrop})
		}
	}
	return nets, nil
}

// ParseNetstatOpenBSD joins OpenBSD's `netstat -ibn` (bytes) and `netstat -in` (packets and failures),
// reading each link-level row from the right, since the address column may be empty.
func ParseNetstatOpenBSD(bytesOut, pktsOut []byte) []report.NetIO {
	byName := map[string]*report.NetIO{}
	var order []string
	links := func(out []byte, want int, f func(dev string, v []uint64)) {
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 3+want || !strings.HasPrefix(fs[2], "<Link") || strings.HasPrefix(fs[0], "lo") {
				continue
			}
			v := make([]uint64, want)
			for i := range want {
				v[i], _ = strconv.ParseUint(fs[len(fs)-want+i], 10, 64)
			}
			f(strings.TrimSuffix(fs[0], "*"), v) // a * marks an interface that's down
		}
	}
	links(bytesOut, 2, func(dev string, v []uint64) {
		byName[dev] = &report.NetIO{Device: dev, RxBytes: v[0], TxBytes: v[1]}
		order = append(order, dev)
	})
	links(pktsOut, 5, func(dev string, v []uint64) {
		if n := byName[dev]; n != nil {
			n.RxErrs, n.TxErrs = v[1], v[3]
		}
	})
	nets := []report.NetIO{}
	for _, d := range order {
		nets = append(nets, *byName[d])
	}
	return nets
}

// ParseLoadavg reads the sysctl vm.loadavg struct of the BSDs on 64-bit systems: three
// uint32 fixed-point averages, padding, then the int64 scale.
func ParseLoadavg(b []byte) ([3]float64, error) {
	var l [3]float64
	if len(b) < 24 {
		return l, fmt.Errorf("vm.loadavg: %d bytes", len(b))
	}
	scale := float64(binary.NativeEndian.Uint64(b[16:24]))
	if scale == 0 {
		return l, fmt.Errorf("vm.loadavg: zero scale")
	}
	for i := range 3 {
		l[i] = float64(binary.NativeEndian.Uint32(b[4*i:])) / scale
	}
	return l, nil
}

// CPUTicks turns kern.cp_time(s) longs into per-CPU seconds. states is CPUSTATES (5 on FreeBSD:
// user nice sys intr idle; 6 on OpenBSD: user nice sys spin intr idle, spin counted as system).
func CPUTicks(b []byte, states int, stathz int) ([]report.CPU, error) {
	if states != 5 && states != 6 || stathz <= 0 || len(b)%(8*states) != 0 || len(b) == 0 {
		return nil, fmt.Errorf("cp_time: %d bytes for %d states at %d Hz", len(b), states, stathz)
	}
	sec := func(i int) float64 { return float64(binary.NativeEndian.Uint64(b[8*i:])) / float64(stathz) }
	var cpus []report.CPU
	for base := 0; base < len(b)/8; base += states {
		c := report.CPU{User: sec(base), Nice: sec(base + 1), System: sec(base + 2)}
		if states == 5 {
			c.IRQ, c.Idle = sec(base+3), sec(base+4)
		} else {
			c.System += sec(base + 3)
			c.IRQ, c.Idle = sec(base+4), sec(base+5)
		}
		cpus = append(cpus, c)
	}
	return cpus, nil
}

// ServiceState reads one rc service's status into a unit state. FreeBSD runs `service NAME status`;
// OpenBSD runs `rcctl check NAME`. A nil err means exit status 0; its text holds what went to stderr.
func ServiceState(goos, name string, out []byte, err error) report.UnitState {
	s := report.UnitState{Unit: name, Load: "loaded", Active: "active", Sub: "running"}
	text := strings.TrimSpace(string(out))
	if err != nil {
		text = strings.TrimSpace(text + "\n" + err.Error())
	}
	switch {
	case strings.Contains(text, "does not exist"):
		s.Load, s.Active, s.Sub = "not-found", "inactive", "dead"
	case strings.Contains(text, "special variable"):
		s.Load, s.Active, s.Sub = "not a service", "inactive", "dead"
	case strings.Contains(text, "unknown directive 'status'"):
		s.Active, s.Sub = "unknown", "no status command"
	case err == nil:
	case goos == "openbsd" && strings.Contains(text, "(failed)"):
		s.Active, s.Sub = "failed", "not running"
	case strings.Contains(text, "is not running"):
		s.Active, s.Sub = "inactive", "not running"
	default:
		s.Active, s.Sub = "unknown", firstLine(text)
	}
	return s
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
