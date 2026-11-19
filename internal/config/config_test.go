package config_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
)

func TestStrictKeys(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"alerts": {"enabld": true}}`, `alerts.enabld: unknown key (did you mean enabled?)`},
		{`{"hostz": {}}`, `hostz: unknown key (did you mean hosts?)`},
		{`{"hosts": {"swapin": {"warn": 5}}}`, `hosts.swapin: unknown key (did you mean swapIn?)`},
		{`{"hosts": {"swapIn": {"wran": 5}}}`, `hosts.swapIn.wran: unknown key (did you mean warn?)`},
		{`{"host": [{"name": "a", "local": true, "unitz": []}]}`, `host[0].unitz: unknown key (did you mean units?)`},
		{`{"host": [{"name": "a", "local": true, "disks": {"/a": {"fre": {}}}}]}`, `host[0].disks["/a"].fre: unknown key (did you mean free?)`},
		{`{"ping": {"interval": "1m", "targets": [{"name": "a", "retrys": 1}]}}`, `ping.targets[0].retrys: unknown key (did you mean retries?)`},
		{`{"zzz": 1}`, `zzz: unknown key`},
		{`{"hosts": {"hosts": []}}`, `hosts.hosts: renamed in 1.5.0: use host`},
		{`{"dns": null}`, `dns: null; leave the key out to turn dns off`},
		{`{"hub": {"lockedAfter": "-1s"}}`, `hub.lockedAfter: negative no longer means off: write "off"`},
		{`{"alerts": {"unknownAfter": -1}}`, `alerts.unknownAfter: negative no longer means off: write "off"`},
		{`{"defaults": {"interval": "off"}}`, `defaults.interval: "off" isn't allowed here`},
		{`{"defaults": {"timeout": "-5s"}}`, `defaults.timeout: must not be negative, got -5s`},
		{`{"hosts": {"disk": {"crit": "of"}}}`, `hosts.disk.crit: want a number or "off"`},
		{`{"alerts": {"enabled": "yes"}}`, `alerts.enabled: want true or false`},
		{`{"alerts": {"to": "ops@example.org"}}`, `alerts.to: want a list`},
		{`{"alerts": {"smtp": "a", "smtp": "b"}}`, `key smtp appears twice`},
	} {
		_, err := config.Parse([]byte(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.in, err, tc.want)
		}
	}
	_, err := config.Parse([]byte(`{"alerts": {"enabld": true}, "hosts": {"Disk": {}}}`))
	if err == nil || !strings.HasPrefix(err.Error(), "config: 2 problems:\n  alerts.enabld") || !strings.Contains(err.Error(), "hosts.Disk: unknown key (did you mean disk?)") {
		t.Errorf("all problems, in order: %v", err)
	}
}

func TestOff(t *testing.T) {
	c, err := config.Parse([]byte(`{"hub": {"lockedAfter": "off"}, "alerts": {"unknownAfter": "off"},
		"hosts": {"diskBusy": {"warn": 95, "crit": "off"}}, "host": [{"name": "a", "local": true, "wireguard": null}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Hub.LockedAfter != config.Off || c.Alerts.UnknownAfter != config.Off {
		t.Errorf("durations = %v %v", c.Hub.LockedAfter, c.Alerts.UnknownAfter)
	}
	b, _ := json.Marshal(c)
	for _, want := range []string{`"lockedAfter":"off"`, `"unknownAfter":"off"`, `"diskBusy":{"warn":95,"crit":"off"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("effective config lacks %s", want)
		}
	}
}

func TestDurationString(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "0s", 10 * time.Second: "10s", 90 * time.Second: "1m30s",
		time.Minute: "1m", time.Hour: "1h", 26 * time.Hour: "26h", 150 * time.Minute: "2h30m", 3601 * time.Second: "1h0m1s", 500 * time.Millisecond: "500ms"} {
		if got := config.Duration(d).String(); got != want {
			t.Errorf("%v = %q, want %q", d, got, want)
		}
	}
}

func TestEffectiveRoundTrip(t *testing.T) {
	c, err := config.Load("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := config.Parse(b)
	if err != nil {
		t.Fatalf("effective config doesn't load: %v", err)
	}
	b2, _ := json.Marshal(c2)
	if string(b) != string(b2) {
		t.Errorf("effective config changes when reloaded:\n%s\n%s", b, b2)
	}
	if !strings.Contains(string(b), `"host":[{"name":"alpha"`) || !strings.Contains(string(b), `"retries":2`) {
		t.Errorf("effective config lacks the host list or defaults: %s", b)
	}
}

func TestTOMLMatchesJSON(t *testing.T) {
	j, err := config.Load("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	tm, err := config.Load("../../testdata/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	bj, _ := json.Marshal(j)
	bt, _ := json.Marshal(tm)
	if string(bj) != string(bt) {
		t.Errorf("TOML and JSON differ:\n%s\n%s", bj, bt)
	}
}

func TestTOMLStrict(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"[hosts]\nswapin = { warn = 5 }\n", `hosts.swapin: unknown key (did you mean swapIn?)`},
		{"[[host]]\nname = \"a\"\nlocal = true\nunitz = []\n", `host[0].unitz: unknown key (did you mean units?)`},
		{"[hosts]\n[[hosts.hosts]]\nname = \"a\"\n", `hosts.hosts: renamed in 1.5.0: use host`},
		{"[hub]\nlockedAfter = -1\n", `hub.lockedAfter: negative no longer means off: write "off"`},
		{"[hosts]\ndisk = { crit = \"off\", warn = \"x\" }\n", `hosts.disk.warn: want a number or "off"`},
		{"[alerts]\ndigestTime = 08:00:00\n", `alerts.digestTime: dates and times aren't used`},
		{"[alerts]\nenabled = true\nenabled = false\n", `line 3`},
		{"[zzz]\n[alerts]\nenabld = true\n", "2 problems:\n  zzz: unknown key\n  alerts.enabld: unknown key (did you mean enabled?)"},
	} {
		_, err := config.ParseTOML([]byte(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestWriteTOMLRoundTrip(t *testing.T) {
	for _, c := range []*config.Config{mustLoad(t, "../../testdata/config.json"), mustLoad(t, "../../testdata/config.toml")} {
		b, _ := json.Marshal(c)
		var out strings.Builder
		if err := config.WriteTOML(&out, b); err != nil {
			t.Fatal(err)
		}
		c2, err := config.ParseTOML([]byte(out.String()))
		if err != nil {
			t.Fatalf("written TOML doesn't load: %v\n%s", err, out.String())
		}
		b2, _ := json.Marshal(c2)
		if string(b) != string(b2) {
			t.Errorf("TOML round trip differs:\n%s\n%s", b, b2)
		}
	}
}

func mustLoad(t *testing.T, path string) *config.Config {
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadNeedsExtension(t *testing.T) {
	if _, err := config.Load("../../testdata/compat/healthz-1.3.0.txt"); err == nil || !strings.Contains(err.Error(), "want a .toml or .json file") {
		t.Errorf("unknown extension: %v", err)
	}
}

// TestConfigReference keeps the docs' reference block equal to `sitescope config -defaults`, comments and blank lines aside.
func TestConfigReference(t *testing.T) {
	page, err := os.ReadFile("../../site/pages/configuration.md")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no docs in this source tree (the Nix package build)")
	}
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(page), "TestConfigReference checks this block")
	if !ok {
		t.Fatal("configuration.md has no reference block")
	}
	_, block, _ = strings.Cut(block, "```toml\n")
	block, _, _ = strings.Cut(block, "```")
	doc, err := config.ReferenceJSON()
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	if err := config.WriteTOML(&want, doc); err != nil {
		t.Fatal(err)
	}
	keep := func(s string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			l, _, _ = strings.Cut(l, "  # ")
			if l = strings.TrimRight(l, " "); l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return out
	}
	got, exp := keep(block), keep(want.String())
	for i := range max(len(got), len(exp)) {
		g, e := "", ""
		if i < len(got) {
			g = got[i]
		}
		if i < len(exp) {
			e = exp[i]
		}
		if g != e {
			t.Fatalf("configuration.md reference differs from sitescope config -defaults at line %d:\n docs: %q\n code: %q", i+1, g, e)
		}
	}
}

// TestDocsTOML checks every TOML example in the docs: its syntax, and that every key exists.
func TestDocsTOML(t *testing.T) {
	pages, _ := filepath.Glob("../../site/pages/*.md")
	if len(pages) == 0 {
		t.Skip("no docs in this source tree (the Nix package build)")
	}
	pages = append(pages, "../../README.md")
	n := 0
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rest := string(b)
		for {
			var block string
			var ok bool
			if _, rest, ok = strings.Cut(rest, "```toml\n"); !ok {
				break
			}
			block, rest, _ = strings.Cut(rest, "```")
			n++
			if err := config.CheckTOMLKeys([]byte(block)); err != nil {
				t.Errorf("%s: TOML example %q...: %v", filepath.Base(p), strings.SplitN(block, "\n", 2)[0], err)
			}
		}
	}
	if n < 5 {
		t.Errorf("only %d TOML examples found", n)
	}
}
