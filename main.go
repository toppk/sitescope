// Command sitescope is a small health monitor: hub, agent and operator CLI in one binary.
package main

import (
	"bytes"
	"context"
	_ "embed"
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

const usage = `usage: sitescope <command> [flags]

daemons:
  hub   -config FILE          poll agents, run probes, serve the status page, send mail
  agent -config FILE          serve this host's report on the wg0 address

operator (on the hub host; paths come from the hub config, -config or $SITESCOPE_CONFIG):
  unlock | lock | status      talk to the running hub over its control socket
  vault set NAME              store a secret (value from stdin)
  vault rm NAME               delete a secret
  vault list                  list secret names
  vault set-password          store the admin password hash for the detail view

  check -config FILE [-match SUBSTR]   run checks once and print results
  probes -config FILE                  list every destination the hub contacts, and how often
  verify -url URL [-version V] [-ca FILE] [-vault STATE] [-overall STATUS] [-services N] [-checks N]
                              read a running hub's /healthz and /status.json and check them
  version
`

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
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "hub":
		err = runHub(args)
	case "agent":
		err = runAgent(args)
	case "check":
		err = runCheck(args)
	case "probes":
		var cfg *config.Config
		if cfg, err = loadConfig(flag.NewFlagSet("probes", flag.ExitOnError), args); err == nil {
			err = hub.Probes(cfg, os.Stdout)
		}
	case "verify":
		err = runVerify(args)
	case "unlock", "lock", "status":
		err = runControl(cmd, args)
	case "vault":
		if err = runVault(args); errors.Is(err, fs.ErrPermission) {
			err = fmt.Errorf("%w (vault commands run as the hub user: sudo -u sitescope sitescope vault ...)", err)
		}
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sitescope:", err)
		os.Exit(1)
	}
}

func defaultConfig() string {
	if p := os.Getenv("SITESCOPE_CONFIG"); p != "" {
		return p
	}
	return "/etc/sitescope/config.json"
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", defaultConfig(), "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

// hubConfig reads the hub's config for the operator commands; a missing default file means built-in paths.
func hubConfig(fs *flag.FlagSet, path string) (*config.Config, error) {
	explicit := os.Getenv("SITESCOPE_CONFIG") != ""
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := config.Load(path)
	if err != nil && !explicit && errors.Is(err, os.ErrNotExist) {
		return config.Parse([]byte("{}"))
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

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	match := fs.String("match", "", "only checks whose id contains this")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	worst, err := hub.CheckOnce(ctx, cfg, *match, os.Stdout)
	if err != nil {
		return err
	}
	if worst == status.Crit {
		os.Exit(2)
	}
	return nil
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
