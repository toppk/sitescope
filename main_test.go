package main

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHubConfigPaths(t *testing.T) {
	t.Setenv("SITESCOPE_CONFIG", "")
	dir := t.TempDir()
	missing := filepath.Join(dir, "none.json")
	parse := func(args ...string) *flag.FlagSet {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.String("config", missing, "")
		fs.Parse(args)
		return fs
	}

	_, err := hubConfig(parse(), missing)
	if err == nil || !strings.Contains(err.Error(), "-config FILE, set $SITESCOPE_CONFIG, or create "+missing) {
		t.Errorf("missing default config: %v", err)
	}
	if _, err := hubConfig(parse("-config", missing), missing); err == nil {
		t.Error("a missing -config file should fail")
	}

	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"hub": {"stateDir": "/home/op/server/sitescope", "controlSocket": "/run/user/1000/sitescope.sock"}}`), 0o600)
	cfg, err := hubConfig(parse(), p)
	if err != nil || cfg.Hub.ControlSocket != "/run/user/1000/sitescope.sock" || cfg.Hub.Vault != "/home/op/server/sitescope/vault.age" {
		t.Errorf("config paths = %+v, %v", cfg.Hub, err)
	}
}

func TestUsageCoversCommands(t *testing.T) {
	u := usage()
	for _, c := range commands {
		for _, line := range c.usage {
			if !strings.HasPrefix(line[0], c.name) || !strings.Contains(u, line[0]) {
				t.Errorf("usage for %s: %q", c.name, line[0])
			}
		}
	}
	if !slices.ContainsFunc(commands, func(c command) bool { return c.name == "config" }) {
		t.Error("config is a command")
	}
}
