// Command sitescope is a small health monitor: hub, agent and operator CLI in one binary.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/toppk/sitescope/internal/agent"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/hub"
	"github.com/toppk/sitescope/internal/secmem"
	"github.com/toppk/sitescope/internal/status"
	"github.com/toppk/sitescope/internal/vault"
)

//go:embed VERSION
var versionFile string

// version is set with -X main.version=X.Y.Z+rev; plain builds fall back to VERSION+dev.
var version string

func init() {
	if version == "" {
		version = strings.TrimSpace(versionFile) + "+dev"
	}
}

type command struct {
	name  string
	group string
	usage [][2]string // synopsis, what it does
	run   func(args []string) error
}

var groups = []string{
	"daemons",
	"operator (on the hub host; paths come from the hub config, -config or $SITESCOPE_CONFIG)",
	"config and checks",
	"",
}

// commands is both the dispatch table and the usage text.
var commands = []command{
	{"hub", groups[0], [][2]string{{"hub -config FILE", "poll agents, run probes, serve the status page, send mail"}}, runHub},
	{"agent", groups[0], [][2]string{{"agent -config FILE", "serve this host's report on the wg0 address"}}, runAgent},
	{"unlock", groups[1], [][2]string{{"unlock", "send the vault passphrase to the running hub"}}, func(a []string) error { return runControl("unlock", a) }},
	{"lock", groups[1], [][2]string{{"lock", "zero the hub's decrypted secrets"}}, func(a []string) error { return runControl("lock", a) }},
	{"status", groups[1], [][2]string{{"status", "print the vault state and check count"}}, func(a []string) error { return runControl("status", a) }},
	{"vault", groups[1], [][2]string{
		{"vault set NAME", "store a secret (value from stdin)"},
		{"vault rm NAME", "delete a secret"},
		{"vault list", "list secret names"},
		{"vault set-password", "store the admin password hash for the detail view"},
	}, func(a []string) error {
		err := runVault(a)
		if errors.Is(err, fs.ErrPermission) {
			err = fmt.Errorf("%w (vault commands run as the hub user: sudo -u sitescope sitescope vault ...)", err)
		}
		return err
	}},
	{"config", groups[2], [][2]string{
		{"config -config FILE [-check] [-format json|nix]", "print the effective config as TOML, every default filled in; -check only validates it"},
		{"config -defaults", "print every key with its built-in default"},
	}, runConfig},
	{"check", groups[2], [][2]string{{"check -config FILE [-match SUBSTR] [-format json]", "run checks once and print results; exits 2 if any is crit"}}, runCheck},
	{"probes", groups[2], [][2]string{{"probes -config FILE [-format json]", "list every destination the hub contacts, and how often"}}, runProbes},
	{"verify", groups[2], [][2]string{{"verify -url URL [-version V] [-ca FILE] [-vault STATE] [-overall STATUS] [-services N] [-checks N]",
		"read a running hub's /healthz and /status.json and check them"}}, runVerify},
	{"version", groups[3], [][2]string{{"version", "print the version"}}, func([]string) error { fmt.Println(version); return nil }},
}

func usage() string {
	var b strings.Builder
	b.WriteString("usage: sitescope <command> [flags]; sitescope <command> -h lists its flags\n")
	for _, g := range groups {
		b.WriteString("\n")
		if g != "" {
			b.WriteString(g + ":\n")
		}
		for _, c := range commands {
			if c.group != g {
				continue
			}
			for _, u := range c.usage {
				if len(u[0]) > 36 {
					fmt.Fprintf(&b, "  %s\n  %-36s %s\n", u[0], "", u[1])
				} else {
					fmt.Fprintf(&b, "  %-36s %s\n", u[0], u[1])
				}
			}
		}
	}
	return b.String()
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{} // journald timestamps
			}
			return a
		},
	})))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage())
		return
	}
	i := slices.IndexFunc(commands, func(c command) bool { return c.name == cmd })
	if i < 0 {
		fmt.Fprintf(os.Stderr, "sitescope: unknown command %q\n\n%s", cmd, usage())
		os.Exit(2)
	}
	if err := commands[i].run(args); err != nil {
		fmt.Fprintln(os.Stderr, "sitescope:", err)
		os.Exit(1)
	}
}

const etcTOML, etcJSON = "/etc/sitescope/config.toml", "/etc/sitescope/config.json"

// defaultConfig is $SITESCOPE_CONFIG, else whichever of /etc/sitescope/config.toml and config.json exists.
func defaultConfig() string {
	if p := os.Getenv("SITESCOPE_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat(etcTOML); err == nil {
		return etcTOML
	}
	return etcJSON
}

// explicitConfig reports whether -config or $SITESCOPE_CONFIG named the file; otherwise both default files may not exist.
func explicitConfig(fs *flag.FlagSet) (bool, error) {
	explicit := os.Getenv("SITESCOPE_CONFIG") != ""
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	if !explicit {
		_, errT := os.Stat(etcTOML)
		_, errJ := os.Stat(etcJSON)
		if errT == nil && errJ == nil {
			return false, fmt.Errorf("both %s and %s exist; remove one, or give -config FILE", etcTOML, etcJSON)
		}
	}
	return explicit, nil
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", defaultConfig(), "config file, .toml or .json")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if _, err := explicitConfig(fs); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

// hubConfig reads the hub's config for the operator commands; without one they could act on the wrong hub.
func hubConfig(fs *flag.FlagSet, path string) (*config.Config, error) {
	explicit, err := explicitConfig(fs)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil && !explicit && errors.Is(err, os.ErrNotExist) {
		if path == etcJSON {
			path = etcTOML + " or " + etcJSON
		}
		return nil, fmt.Errorf("no hub config: give -config FILE, set $SITESCOPE_CONFIG, or create %s", path)
	}
	return cfg, err
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}

func runHub(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("hub", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	if err := secmem.HardenProcess(); err != nil {
		return fmt.Errorf("harden: %w", err)
	}
	hub.Version = version
	h, err := hub.New(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	return h.Run(ctx)
}

func runAgent(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("agent", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	peers := cfg.Agent.WGPeers
	if hs := config.Get[*check.Hosts](cfg); len(peers) == 0 && hs != nil {
		peers = hs.WGPeers
	}
	s := &agent.Server{Collector: &agent.Collector{Cfg: cfg.Agent}, Token: os.Getenv("SITESCOPE_AGENT_TOKEN"),
		Version: version, Peers: peers}
	tc, err := agent.TLSConfig(cfg.Agent.TLSCert, cfg.Agent.TLSKey)
	if err != nil {
		return err
	}
	return agent.Run(ctx, cfg.Agent.Listen, s, tc)
}

// formatFlag adds -format; text and json render the same value.
func formatFlag(fs *flag.FlagSet) func() (bool, error) {
	f := fs.String("format", "text", "output format: text or json")
	return func() (bool, error) {
		switch *f {
		case "text":
			return false, nil
		case "json":
			return true, nil
		}
		return false, fmt.Errorf("-format %q, want text or json", *f)
	}
}

func writeJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	match := fs.String("match", "", "only checks whose id contains this")
	format := formatFlag(fs)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	asJSON, err := format()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	rows, err := hub.CheckOnce(ctx, cfg, *match)
	if err != nil {
		return err
	}
	if asJSON {
		err = writeJSON(rows)
	} else {
		hub.WriteChecks(os.Stdout, rows)
	}
	if err != nil {
		return err
	}
	if slices.ContainsFunc(rows, func(r hub.CheckResult) bool { return r.Status == status.Crit }) {
		os.Exit(2)
	}
	return nil
}

func runProbes(args []string) error {
	fs := flag.NewFlagSet("probes", flag.ExitOnError)
	format := formatFlag(fs)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	asJSON, err := format()
	if err != nil {
		return err
	}
	rep, err := hub.Probes(cfg)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSON(rep)
	}
	hub.WriteProbes(os.Stdout, rep)
	return nil
}

func runConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	only := fs.Bool("check", false, "validate the config and build its checks; print nothing but a count")
	ref := fs.Bool("defaults", false, "print every key with its built-in default, instead of reading a config")
	format := fs.String("format", "toml", "output format: toml, json, or nix for services.sitescope.settings")
	path := fs.String("config", defaultConfig(), "config file, .toml or .json")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("config: unexpected argument %q", fs.Arg(0))
	}
	if *format != "toml" && *format != "json" && *format != "nix" {
		return fmt.Errorf("-format %q, want toml, json or nix", *format)
	}
	cfg := config.Reference()
	if !*ref {
		if _, err := explicitConfig(fs); err != nil {
			return err
		}
		var err error
		if cfg, err = config.Load(*path); err != nil {
			return err
		}
		checks, err := check.Build(cfg)
		if err != nil {
			return err
		}
		if *only {
			fmt.Printf("config ok: %d checks\n", len(checks))
			return nil
		}
	}
	doc, err := json.Marshal(cfg)
	if *ref {
		doc, err = config.ReferenceJSON()
	}
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		var out bytes.Buffer
		json.Indent(&out, doc, "", "  ")
		out.WriteByte('\n')
		_, err := out.WriteTo(os.Stdout)
		return err
	case "nix":
		return config.WriteNix(os.Stdout, doc)
	}
	return config.WriteTOML(os.Stdout, doc)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	url := fs.String("url", "", "the hub's base URL")
	var want hub.Expect
	fs.StringVar(&want.Version, "version", "", "expected version, X.Y.Z or X.Y.Z+rev")
	fs.StringVar(&want.Vault, "vault", "", "expected vault state: locked or unlocked")
	fs.StringVar(&want.Overall, "overall", "", "expected overall status: ok, warn, crit or unknown")
	fs.IntVar(&want.Services, "services", -1, "expected number of services in /status.json")
	fs.IntVar(&want.Checks, "checks", -1, "expected number of checks in /status.json")
	ca := fs.String("ca", "", "PEM file of the only CA to trust for the hub's certificate")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout for each request")
	fs.Parse(args)
	if *url == "" || fs.NArg() > 0 {
		return errors.New("verify: -url URL is required, and takes no arguments")
	}
	switch want.Vault {
	case "", "locked", "unlocked":
	default:
		return fmt.Errorf("verify: -vault %q, want locked or unlocked", want.Vault)
	}
	if want.Overall != "" {
		if _, err := status.ParseStatus(want.Overall); err != nil {
			return fmt.Errorf("verify: -overall: %w", err)
		}
	}
	c := &http.Client{}
	if *ca != "" {
		var err error
		if c, err = check.CAClient(*ca); err != nil {
			return fmt.Errorf("verify: -ca: %w", err)
		}
	}
	c.Timeout = *timeout
	ctx, cancel := signalContext()
	defer cancel()
	return hub.Verify(ctx, c, *url, want, os.Stdout)
}

func runControl(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig(), "hub config, for hub.controlSocket")
	sock := fs.String("socket", "", "hub control socket (default hub.controlSocket)")
	fs.Parse(args)
	if *sock == "" {
		cfg, err := hubConfig(fs, *cfgPath)
		if err != nil {
			return err
		}
		*sock = cfg.Hub.ControlSocket
	}
	var pass *secmem.Buf
	n := 0
	if cmd == "unlock" {
		var err error
		if pass, n, err = hub.ReadSecret("vault passphrase: "); err != nil {
			return err
		}
		defer pass.Destroy()
	}
	conn, err := net.DialTimeout("unix", *sock, 5*time.Second)
	if err != nil {
		return fmt.Errorf("%w (is the hub running, and are you in its admin group?)", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Minute))
	fmt.Fprintf(conn, "%s\n", cmd)
	if pass != nil {
		conn.Write(pass.Bytes()[:n])
	}
	conn.(*net.UnixConn).CloseWrite()
	reply, _ := io.ReadAll(io.LimitReader(conn, 4096))
	line := strings.TrimSpace(string(reply))
	if msg, ok := strings.CutPrefix(line, "ok "); ok {
		fmt.Println(msg)
		return nil
	}
	return errors.New(strings.TrimPrefix(line, "err "))
}

func runVault(args []string) error {
	if len(args) < 1 {
		return errors.New("vault: want set, rm, list or set-password")
	}
	sub := args[0]
	fs := flag.NewFlagSet("vault "+sub, flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig(), "hub config, for hub.vault")
	path := fs.String("vault", "", "vault file (default hub.vault)")
	fs.Parse(args[1:])
	if *path == "" {
		cfg, err := hubConfig(fs, *cfgPath)
		if err != nil {
			return err
		}
		*path = cfg.Hub.Vault
	}
	name := fs.Arg(0)
	switch sub {
	case "set", "rm":
		if !vault.ValidName(name) {
			return fmt.Errorf("vault %s: need a NAME of letters, digits, _ . -", sub)
		}
	case "list", "set-password":
	default:
		return fmt.Errorf("vault: unknown subcommand %q", sub)
	}

	pass, n, base, err := openVault(*path, sub == "set" || sub == "set-password")
	if err != nil {
		return err
	}
	defer pass.Destroy()
	defer base.Destroy()
	p := pass.Bytes()[:n]

	edit := vault.NewEdit()
	defer edit.Destroy()
	switch sub {
	case "list":
		for _, nm := range base.Names() {
			fmt.Println(nm)
		}
		return nil
	case "rm":
		if _, ok := base.Get(name); !ok {
			return vault.ErrNotFound
		}
		edit.Remove(name)
	case "set":
		v, vn, err := hub.ReadStdinSecret("value for "+name+": ", vault.MaxSize)
		if err != nil {
			return err
		}
		defer v.Destroy()
		if vn == 0 {
			return errors.New("empty value")
		}
		if err := edit.Set(name, v.Bytes()[:vn]); err != nil {
			return err
		}
	case "set-password":
		pw, err := promptTwice("admin password for the detail view: ")
		if err != nil {
			return err
		}
		defer pw.buf.Destroy()
		hash, err := bcrypt.GenerateFromPassword(pw.buf.Bytes()[:pw.n], 12)
		if err != nil {
			return err
		}
		edit.Set(hub.AdminSecret, hash)
		secmem.Wipe(hash)
	}
	if err := vault.Save(*path, p, base, edit); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "saved. A running hub picks this up on the next `sitescope unlock`.")
	return nil
}

type secret struct {
	buf *secmem.Buf
	n   int
}

func promptTwice(prompt string) (secret, error) {
	a, an, err := hub.ReadSecret(prompt)
	if err != nil {
		return secret{}, err
	}
	b, bn, err := hub.ReadSecret("again: ")
	if err != nil {
		a.Destroy()
		return secret{}, err
	}
	defer b.Destroy()
	if an != bn || !bytes.Equal(a.Bytes()[:an], b.Bytes()[:bn]) {
		a.Destroy()
		return secret{}, errors.New("entries do not match")
	}
	if an == 0 {
		a.Destroy()
		return secret{}, errors.New("empty")
	}
	return secret{a, an}, nil
}

// openVault asks for the passphrase and decrypts the vault; with create set,
// a missing vault starts empty after the new passphrase is confirmed.
func openVault(path string, create bool) (*secmem.Buf, int, *vault.Secrets, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, 0, nil, fmt.Errorf("no vault at %s", path)
		}
		fmt.Fprintf(os.Stderr, "creating a new vault at %s\n", path)
		s, err := promptTwice("new vault passphrase: ")
		return s.buf, s.n, nil, err
	}
	pass, n, err := hub.ReadSecret("vault passphrase: ")
	if err != nil {
		return nil, 0, nil, err
	}
	s, err := vault.Load(path, pass.Bytes()[:n])
	if err != nil {
		pass.Destroy()
		return nil, 0, nil, err
	}
	return pass, n, s, nil
}
