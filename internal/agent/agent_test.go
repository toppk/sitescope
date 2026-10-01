package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/config"
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
	write(t, root, "/proc/uptime", "12345.67 100.0\n")
	write(t, root, "/proc/loadavg", "0.10 0.20 0.30 1/100 999\n")
	write(t, root, "/proc/meminfo", "MemTotal:  1000000 kB\nMemFree: 1 kB\nMemAvailable:  400000 kB\nSwapTotal: 524284 kB\nSwapFree: 524000 kB\n")
	// root fs plus a PrivateTmp-style bind of the same device, and a tmpfs to ignore
	write(t, root, "/proc/self/mountinfo", "22 1 8:0 / / rw - ext4 /dev/sda rw\n"+
		"30 22 8:0 /tmp/systemd-private-x /tmp rw - ext4 /dev/sda rw\n"+
		"31 22 0:5 / /run rw - tmpfs tmpfs rw\n")
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
