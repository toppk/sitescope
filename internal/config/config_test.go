package config_test

import (
	"encoding/json"
	"strings"
	"testing"

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
	for _, want := range []string{`"lockedAfter":"off"`, `"unknownAfter":"off"`, `"diskBusy":{"crit":"off","warn":95}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("effective config lacks %s", want)
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
