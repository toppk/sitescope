package agent

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/toppk/sitescope/internal/report"
)

func TestParseSwapinfo(t *testing.T) {
	out := "Device          1K-blocks     Used    Avail Capacity\n/dev/vtbd0p2      2097152     1024  2096128     0%\n/dev/md0           524288      512   523776     0%\nTotal             2621440     1536  2619904     0%\n"
	total, used, err := ParseSwapinfo([]byte(out))
	if err != nil || total != 2621440 || used != 1536 {
		t.Errorf("swapinfo = %d %d %v", total, used, err)
	}
	if total, used, err := ParseSwapinfo([]byte("Device          1K-blocks     Used    Avail Capacity\n")); err != nil || total != 0 || used != 0 {
		t.Errorf("no swap = %d %d %v", total, used, err)
	}
}

func TestParseNetstatJSON(t *testing.T) {
	out := `{"statistics": {"interface": [{"name":"vtnet0","network":"<Link#1>","address":"5e:43:02:72:54:0e","received-packets":52717,"received-errors":1,"dropped-packets":2,"received-bytes":71811019,"sent-packets":27216,"send-errors":3,"sent-bytes":2095879,"collisions":0},
{"name":"vtnet0","network":"192.168.122.0/24","address":"192.168.122.91","received-packets":50051,"received-bytes":70856863,"sent-packets":27209,"sent-bytes":1714455},
{"name":"lo0","network":"<Link#2>","address":"lo0","received-bytes":411272,"sent-bytes":411272}]}}`
	nets, err := ParseNetstatJSON([]byte(out))
	want := report.NetIO{Device: "vtnet0", RxBytes: 71811019, TxBytes: 2095879, RxErrs: 1, TxErrs: 3, RxDrop: 2}
	if err != nil || len(nets) != 1 || nets[0] != want {
		t.Errorf("netstat json = %+v %v", nets, err)
	}
}

func TestParseNetstatOpenBSD(t *testing.T) {
	b := "Name    Mtu   Network     Address               Ibytes     Obytes\nlo0     32768 <Link>                            429823     429823\nvio0    1500  <Link>      52:54:00:aa:bb:cc   9000       8000\nenc0*   0     <Link>                            0          0\nvio0    1500  192.168.1/24 192.168.1.5        9000       8000\n"
	p := "Name    Mtu   Network     Address              Ipkts Ifail    Opkts Ofail Colls\nlo0     32768 <Link>                            1713     0     1713     0     0\nvio0    1500  <Link>      52:54:00:aa:bb:cc     90     4       80     5     0\n"
	nets := ParseNetstatOpenBSD([]byte(b), []byte(p))
	want := report.NetIO{Device: "vio0", RxBytes: 9000, TxBytes: 8000, RxErrs: 4, TxErrs: 5}
	if len(nets) != 2 || nets[0] != want || nets[1].Device != "enc0" {
		t.Errorf("netstat = %+v", nets)
	}
}

func TestParseLoadavg(t *testing.T) {
	b := make([]byte, 24)
	for i, v := range []uint32{358, 225, 184} {
		binary.NativeEndian.PutUint32(b[4*i:], v)
	}
	binary.NativeEndian.PutUint64(b[16:], 1024)
	l, err := ParseLoadavg(b)
	if err != nil || l[0] < 0.349 || l[0] > 0.351 || l[2] < 0.179 || l[2] > 0.181 {
		t.Errorf("loadavg = %v %v", l, err)
	}
	if _, err := ParseLoadavg(b[:8]); err == nil {
		t.Error("a short struct is an error")
	}
}

func TestCPUTicks(t *testing.T) {
	longs := func(v ...uint64) []byte {
		b := make([]byte, 8*len(v))
		for i, x := range v {
			binary.NativeEndian.PutUint64(b[8*i:], x)
		}
		return b
	}
	// FreeBSD kern.cp_times: two CPUs of user nice sys intr idle, at stathz 127
	cpus, err := CPUTicks(longs(127, 0, 254, 127, 1270, 254, 0, 127, 0, 1270), 5, 127)
	if err != nil || len(cpus) != 2 || cpus[0] != (report.CPU{User: 1, System: 2, IRQ: 1, Idle: 10}) || cpus[1].User != 2 {
		t.Errorf("freebsd = %+v %v", cpus, err)
	}
	// OpenBSD kern.cp_time: user nice sys spin intr idle, spin counted as system
	cpus, err = CPUTicks(longs(100, 0, 100, 100, 50, 1000), 6, 100)
	if err != nil || len(cpus) != 1 || cpus[0] != (report.CPU{User: 1, System: 2, IRQ: 0.5, Idle: 10}) {
		t.Errorf("openbsd = %+v %v", cpus, err)
	}
	if _, err := CPUTicks(longs(1, 2, 3), 5, 100); err == nil {
		t.Error("a partial CPU is an error")
	}
}

func TestServiceState(t *testing.T) {
	exit1 := errors.New("exit status 1")
	for _, tc := range []struct {
		goos, out         string
		err               error
		load, active, sub string
	}{
		{"freebsd", "sshd is running as pid 1519.", nil, "loaded", "active", "running"},
		{"freebsd", "newsyslog is not running.", exit1, "loaded", "inactive", "not running"},
		{"freebsd", "nosuchd does not exist in /etc/rc.d or the local startup\ndirectories", exit1, "not-found", "inactive", "dead"},
		{"freebsd", "/etc/rc.d/hostid: unknown directive 'status'.", exit1, "loaded", "unknown", "no status command"},
		{"openbsd", "sshd(ok)", nil, "loaded", "active", "running"},
		{"openbsd", "smtpd(failed)", exit1, "loaded", "failed", "not running"},
		{"openbsd", "", errors.New(`rcctl: exit status 1: rcctl: "pf" is a special variable, no rc.d(8) script`), "not a service", "inactive", "dead"},
		{"openbsd", "", errors.New("rcctl: exit status 2: rcctl: service nosuchd does not exist"), "not-found", "inactive", "dead"},
	} {
		s := ServiceState(tc.goos, "x", []byte(tc.out), tc.err)
		if s.Load != tc.load || s.Active != tc.active || s.Sub != tc.sub {
			t.Errorf("%s %q = %s %s %s", tc.goos, tc.out, s.Load, s.Active, s.Sub)
		}
	}
}
