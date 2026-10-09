package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

func TestParsers(t *testing.T) {
	peers, err := ParseHandshakes([]byte("AAA=\t1790000000\nBBB=\t0\n"))
	if err != nil || len(peers) != 2 || peers[0].LatestHandshake != 1790000000 || peers[1].LatestHandshake != 0 {
		t.Fatalf("handshakes = %+v %v", peers, err)
	}

	now := time.Unix(1790003600, 0)
	q, err := ParsePostqueue([]byte(`{"queue_name":"deferred","queue_id":"A1","arrival_time":1790000000,"recipients":[]}
{"queue_name":"active","queue_id":"B2","arrival_time":1790003000,"recipients":[]}
`), now)
	if err != nil || q.Messages != 2 || q.OldestAgeSec != 3600 {
		t.Fatalf("postqueue = %+v %v", q, err)
	}
	if q, _ := ParsePostqueue(nil, now); q.Messages != 0 {
		t.Fatal("empty queue")
	}

	zones := ParseKnotStatus([]byte(`[example.org.] role: slave | serial: 2026100101 | transaction: none | freeze: no | refresh: +3h59m | update: idle | expiration: +27D23h59m10s | journal load: not scheduled
[example.net.] role: secondary | serial: 7 | expiration: -1h
[primary.org.] role: master | serial: 5 | expiration: not scheduled
`))
	if len(zones) != 3 {
		t.Fatalf("zones = %+v", zones)
	}
	if z := zones[0]; z.Name != "example.org" || z.Serial != 2026100101 || z.ExpiresInSec != 27*86400+23*3600+59*60+10 {
		t.Errorf("zone 0 = %+v", z)
	}
	if zones[1].ExpiresInSec != -3600 || zones[2].ExpiresInSec != -1 {
		t.Errorf("expiry parsing = %+v", zones)
	}
}

func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeRoot(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "/etc/os-release", "NAME=NixOS\nID=nixos\nVERSION_ID=\"26.05\"\nPRETTY_NAME=\"NixOS 26.05 (Yarara)\"\n")
	write(t, root, "/proc/uptime", "12345.67 100.0\n")
	write(t, root, "/proc/loadavg", "0.10 0.20 0.30 1/100 999\n")
	write(t, root, "/proc/meminfo", "MemTotal:  1000000 kB\nMemFree: 1 kB\nMemAvailable:  400000 kB\nSwapTotal: 524284 kB\nSwapFree: 524000 kB\n")
	// root fs plus a PrivateTmp-style bind of the same device, and a tmpfs to ignore
	write(t, root, "/proc/self/mountinfo", "22 1 8:0 / / rw - ext4 /dev/sda rw\n"+
		"30 22 8:0 /tmp/systemd-private-x /tmp rw - ext4 /dev/sda rw\n"+
		"31 22 0:5 / /run rw - tmpfs tmpfs rw\n")
	write(t, root, "/proc/stat", "cpu  200 0 100 9600 50 0 10 40 0 0\ncpu0 200 0 100 9600 50 0 10 40 0 0\nintr 1\nbtime 1790000000\n")
	write(t, root, "/proc/vmstat", "nr_free_pages 1\npgmajfault 77\npswpin 5\npswpout 6\noom_kill 1\n")
	write(t, root, "/proc/diskstats", "   8       0 sda 100 0 2048 0 50 0 4096 0 0 1500 0 0 0 0 0 0 0\n"+
		"   8       1 sda1 1 0 8 0 1 0 8 0 0 1 0 0 0 0 0 0 0\n   7       0 loop0 1 0 8 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")
	write(t, root, "/proc/net/dev", "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"+
		"    lo: 9 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\n  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n   wg0: 500 5 0 0 0 0 0 0 600 6 0 0 0 0 0 0\n")
	for _, res := range []string{"cpu", "memory", "io"} {
		write(t, root, "/proc/pressure/"+res, "some avg10=0.00 avg60=1.50 avg300=0.00 total=2000000\nfull avg10=0.00 avg60=0.50 avg300=0.00 total=1000000\n")
	}
	write(t, root, "/sys/fs/cgroup/system.slice/sitescope.service/memory.current", "20971520\n")
	write(t, root, "/sys/fs/cgroup/system.slice/sitescope.service/memory.max", "67108864\n")
	write(t, root, "/sys/fs/cgroup/system.slice/knot.service/memory.current", "83886080\n")
	write(t, root, "/sys/fs/cgroup/system.slice/knot.service/memory.max", "max\n")
	gen := func(name, kernel string) {
		write(t, root, "/nix/store/"+name+"/nixos-version", "26.05.20260920.78e9c78 (Yarara)\n")
		os.Symlink(filepath.Join(root, "/nix/store", kernel), filepath.Join(root, "/nix/store", name, "kernel"))
	}
	os.MkdirAll(filepath.Join(root, "/run"), 0o755)
	gen("sys-a", "k1")
	gen("sys-b", "k1")
	os.Symlink(filepath.Join(root, "/nix/store/sys-a"), filepath.Join(root, "/run/booted-system"))
	os.Symlink(filepath.Join(root, "/nix/store/sys-b"), filepath.Join(root, "/run/current-system"))
	return root
}

func TestCollect(t *testing.T) {
	root := fakeRoot(t)
	c := &Collector{Root: root, Cfg: config.Agent{Systemctl: "/bin/false", WG: "/bin/false", WGInterface: "wg0"}}
	r := c.Collect(context.Background())
	if r.UptimeSec != 12345.67 || r.Load[2] != 0.3 || r.Memory.AvailableKB != 400000 {
		t.Errorf("basic facts: %+v", r)
	}
	if len(r.Disks) != 1 || r.Disks[0].Mount != "/" {
		t.Errorf("disks = %+v", r.Disks)
	}
	if r.OS == nil || r.OS.ID != "nixos" || r.OS.Name != "NixOS 26.05 (Yarara)" {
		t.Errorf("os = %+v", r.OS)
	}
	if r.System.RebootNeeded || r.System.NixpkgsDate != "20260920" {
		t.Errorf("system = %+v", r.System)
	}
	if r.Errors["units"] == "" || r.Errors["wireguard"] == "" {
		t.Errorf("failing commands should be reported per section: %v", r.Errors)
	}

	// a new kernel in the current generation needs a reboot
	os.Remove(filepath.Join(root, "/nix/store/sys-b/kernel"))
	os.Symlink(filepath.Join(root, "/nix/store/k2"), filepath.Join(root, "/nix/store/sys-b/kernel"))
	if r := c.Collect(context.Background()); !r.System.RebootNeeded {
		t.Error("kernel change not detected")
	}
}

func TestCollectNotNixOS(t *testing.T) {
	root := fakeRoot(t)
	os.Remove(filepath.Join(root, "/run/booted-system"))
	os.Remove(filepath.Join(root, "/run/current-system"))
	write(t, root, "/etc/os-release", "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n")
	c := &Collector{Root: root, Cfg: config.Agent{Systemctl: "/bin/false", WG: "/bin/false", WireGuard: new(bool)}}
	r := c.Collect(context.Background())
	if r.OS == nil || r.OS.ID != "fedora" || r.OS.VersionID != "44" {
		t.Errorf("os = %+v", r.OS)
	}
	if _, ok := r.Errors["system"]; ok {
		t.Errorf("NixOS facts are skipped elsewhere: %v", r.Errors)
	}
	if _, ok := r.Errors["wireguard"]; ok {
		t.Errorf("wireguard false skips WireGuard: %v", r.Errors)
	}
}

func TestServerAuth(t *testing.T) {
	s := &Server{Collector: &Collector{Root: fakeRoot(t), Cfg: config.Agent{Systemctl: "/bin/false", WG: "/bin/false"}}, Token: "tok"}
	for hdr, want := range map[string]int{"": 401, "Bearer nope": 401, "Bearer tok": 200} {
		req := httptest.NewRequest("GET", "/v1/report", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("auth %q: %d, want %d", hdr, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/other", nil))
	if w.Code != http.StatusNotFound {
		t.Error("unknown path")
	}
}

func TestCounters(t *testing.T) {
	c := &Collector{Root: fakeRoot(t), Cfg: config.Agent{Systemctl: "/bin/false", WG: "/bin/false"}}
	r := c.Collect(context.Background())
	k := r.Counters
	if k == nil || r.Errors["counters"] != "" {
		t.Fatalf("counters: %v", r.Errors)
	}
	if len(k.CPU) != 1 || k.CPU[0].Idle != 96 || k.CPU[0].Steal != 0.4 || k.BootTime != 1790000000 {
		t.Errorf("cpu = %+v boot %d", k.CPU, k.BootTime)
	}
	if k.VM.OOMKill != 1 || k.VM.PswpIn != 5 || k.VM.PgMajFault != 77 {
		t.Errorf("vmstat = %+v", k.VM)
	}
	if len(k.Disks) != 1 || k.Disks[0].Device != "sda" || k.Disks[0].ReadBytes != 2048*512 || k.Disks[0].IOTimeMS != 1500 {
		t.Errorf("disks (partitions and loop skipped) = %+v", k.Disks)
	}
	if len(k.Net) != 2 || k.Net[0].Device != "eth0" || k.Net[0].TxDrop != 4 {
		t.Errorf("net (lo skipped) = %+v", k.Net)
	}
	if p := k.Pressure["memory"]; p.SomeTotalUS != 2000000 || p.FullAvg60 != 0.5 {
		t.Errorf("psi = %+v", p)
	}
	if len(r.Units) != 2 {
		t.Fatalf("units = %+v", r.Units)
	}
	for _, u := range r.Units {
		if u.Unit == "knot.service" && u.MaxBytes != 0 || u.Unit == "sitescope.service" && u.MaxBytes != 64<<20 {
			t.Errorf("unit %+v", u)
		}
	}
	tr := ParseTransfer([]byte("AAA=\t100\t200\nBBB=\t0\t0\n"))
	if tr["AAA="] != [2]uint64{100, 200} {
		t.Errorf("transfer = %v", tr)
	}
}

var (
	promSample = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*"(?:,[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*")*\})? (\S+)$`)
	promType   = regexp.MustCompile(`^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge|untyped|summary|histogram)$`)
)

// validProm checks text format 0.0.4: one TYPE per family before its samples, samples
// grouped by family, valid names, labels and values, and no duplicate series.
func validProm(t *testing.T, text string) map[string]int {
	t.Helper()
	families := map[string]int{}
	series := map[string]bool{}
	current, done := "", map[string]bool{}
	for i, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# HELP "):
		case strings.HasPrefix(l, "# TYPE "):
			m := promType.FindStringSubmatch(l)
			if m == nil || done[m[1]] {
				t.Fatalf("line %d: bad or repeated TYPE: %q", i+1, l)
			}
			if current != "" {
				done[current] = true
			}
			current = m[1]
		default:
			m := promSample.FindStringSubmatch(l)
			if m == nil {
				t.Fatalf("line %d: bad sample: %q", i+1, l)
			}
			if m[1] != current {
				t.Fatalf("line %d: sample %s outside its family %s", i+1, m[1], current)
			}
			if _, err := strconv.ParseFloat(m[3], 64); err != nil {
				t.Fatalf("line %d: bad value %q", i+1, m[3])
			}
			if series[m[1]+m[2]] {
				t.Fatalf("line %d: duplicate series %s%s", i+1, m[1], m[2])
			}
			series[m[1]+m[2]] = true
			families[m[1]]++
		}
	}
	return families
}

func TestMetrics(t *testing.T) {
	c := &Collector{Root: fakeRoot(t), Cfg: config.Agent{Systemctl: "/bin/false", WG: "/bin/false"}}
	r := c.Collect(context.Background())
	r.WireGuard = []report.WGPeer{{PublicKey: "KEY1=", LatestHandshake: 1790000000, RxBytes: 5}, {PublicKey: "KEY2="}}
	r.Postfix = &report.Postfix{Messages: 3, Queues: map[string]int{"deferred": 2, "active": 1}, OldestAgeSec: 60}
	var b strings.Builder
	WriteMetrics(&b, r, map[string]string{"KEY1=": "se2"}, map[string]uint64{"units": 2}, "abc123", time.Unix(1790003600, 0))
	out := b.String()
	fams := validProm(t, out)
	for _, want := range []string{"node_cpu_seconds_total", "node_memory_MemAvailable_bytes", "node_filesystem_avail_bytes",
		"node_disk_io_time_seconds_total", "node_network_receive_bytes_total", "node_pressure_memory_stalled_seconds_total",
		"node_vmstat_oom_kill", "sitescope_systemd_unit_memory_max_bytes", "sitescope_postfix_queue_messages",
		"sitescope_wireguard_latest_handshake_seconds", "sitescope_agent_collect_errors_total", "sitescope_agent_build_info"} {
		if fams[want] == 0 {
			t.Errorf("missing %s", want)
		}
	}
	if fams["node_cpu_seconds_total"] != 8 || fams["sitescope_systemd_unit_memory_max_bytes"] != 1 {
		t.Errorf("series counts: %v", fams)
	}
	for _, want := range []string{`node_cpu_seconds_total{cpu="0",mode="steal"} 0.4`, `peer="se2"`, `peer="unnamed1"`,
		`node_filesystem_avail_bytes{device="/dev/sda",fstype="ext4",mountpoint="/"}`, `queue="deferred"} 2`,
		`node_memory_MemAvailable_bytes 4.096e+08`} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(out, "KEY1") || strings.Contains(out, "host=") {
		t.Error("no keys or host labels in metrics")
	}
	if len(out) > 50<<10 {
		t.Errorf("metrics are %d bytes", len(out))
	}
}

func writeCert(t *testing.T, dir, cn string) (string, string, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	c, _ := x509.ParseCertificate(der)
	return cf, kf, c
}

func TestAgentTLS(t *testing.T) {
	if _, err := TLSConfig("cert.pem", ""); err == nil {
		t.Error("a cert without a key is a config error")
	}
	if tc, err := TLSConfig("", ""); tc != nil || err != nil {
		t.Error("no cert means plain HTTP")
	}
	dir := t.TempDir()
	cf, kf, first := writeCert(t, dir, "one")
	tc, err := TLSConfig(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: &Server{Collector: &Collector{Root: fakeRoot(t)}, Token: "tok"}}
	go srv.Serve(tls.NewListener(ln, tc))
	defer srv.Close()
	get := func(ca *x509.Certificate) (*http.Response, error) {
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		return c.Get("https://" + ln.Addr().String() + "/healthz")
	}
	if resp, err := get(first); err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz over TLS: %v", err)
	}
	_, _, second := writeCert(t, dir, "two")
	os.Chtimes(cf, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if resp, err := get(second); err != nil || resp.StatusCode != 200 {
		t.Errorf("a renewed cert is picked up without a restart: %v", err)
	}
}
