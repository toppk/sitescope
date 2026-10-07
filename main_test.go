package main

import (
	"flag"
	"os"
	"path/filepath"
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

	cfg, err := hubConfig(parse(), missing)
	if err != nil || cfg.Hub.ControlSocket != "/run/sitescope/control.sock" || cfg.Hub.Vault != "/var/lib/sitescope/vault.age" {
		t.Errorf("missing default config = %+v, %v", cfg, err)
	}
	if _, err := hubConfig(parse("-config", missing), missing); err == nil {
		t.Error("a missing -config file should fail")
	}

	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"hub": {"stateDir": "/home/op/server/sitescope", "controlSocket": "/run/user/1000/sitescope.sock"}}`), 0o600)
	cfg, err = hubConfig(parse(), p)
	if err != nil || cfg.Hub.ControlSocket != "/run/user/1000/sitescope.sock" || cfg.Hub.Vault != "/home/op/server/sitescope/vault.age" {
		t.Errorf("config paths = %+v, %v", cfg.Hub, err)
	}
}
