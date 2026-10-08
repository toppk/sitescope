// Package config loads the JSON config written by the NixOS module; check modules register their own sections.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"time"
)

type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n float64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"5m\" or seconds: %w", err)
		}
		*d = Duration(n * float64(time.Second))
		return nil
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Timing overrides the scheduler defaults for a section or target.
type Timing struct {
	Interval      Duration `json:"interval,omitempty"`
	Timeout       Duration `json:"timeout,omitempty"`
	Retries       *int     `json:"retries,omitempty"`
	RetryInterval Duration `json:"retryInterval,omitempty"`
}

// Merge fills unset fields of t from parent.
func (t Timing) Merge(parent Timing) Timing {
	if t.Interval == 0 {
		t.Interval = parent.Interval
	}
	if t.Timeout == 0 {
		t.Timeout = parent.Timeout
	}
	if t.Retries == nil {
		t.Retries = parent.Retries
	}
	if t.RetryInterval == 0 {
		t.RetryInterval = parent.RetryInterval
	}
	return t
}

type Config struct {
	Hub      Hub      `json:"hub"`
	Agent    Agent    `json:"agent"`
	Alerts   Alerts   `json:"alerts"`
	Defaults Timing   `json:"defaults"`
	Public   []Public `json:"public"`

	// sections are the registered check modules' blocks, in registration order.
	sections []Section
}

// Section is a check module's top-level config block.
type Section interface {
	// Defaults runs after the hub, agent and alert defaults, so it may read them.
	Defaults(c *Config)
	Validate() error
}

var registry []struct {
	key string
	new func() Section
}

// Register adds a top-level config key; check modules call it from init.
func Register(key string, new func() Section) {
	registry = append(registry, struct {
		key string
		new func() Section
	}{key, new})
}

// Sections returns the configured blocks in registration order.
func (c *Config) Sections() []Section { return c.sections }

// Get returns the configured block of type T, or the zero T when absent.
func Get[T Section](c *Config) T {
	for _, s := range c.sections {
		if t, ok := s.(T); ok {
			return t
		}
	}
	var zero T
	return zero
}

func (c *Config) UnmarshalJSON(b []byte) error {
	type core Config
	if err := json.Unmarshal(b, (*core)(c)); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	c.sections = nil
	for _, r := range registry {
		v, ok := raw[r.key]
		if !ok || string(v) == "null" {
			continue
		}
		s := r.new()
		if err := json.Unmarshal(v, s); err != nil {
			return fmt.Errorf("%s: %w", r.key, err)
		}
		c.sections = append(c.sections, s)
	}
	return nil
}

type Hub struct {
	Listen        string   `json:"listen"`
	StateDir      string   `json:"stateDir"`
	ControlSocket string   `json:"controlSocket"`
	ControlGroup  string   `json:"controlGroup"`
	Vault         string   `json:"vault"`
	PublicURL     string   `json:"publicURL"`
	Hostname      string   `json:"hostname"`
	Title         string   `json:"title"`
	Refresh       int      `json:"refresh"`
	DocsURL       string   `json:"docsURL"`
	RetentionDays int      `json:"retentionDays"`
	SampleEvery   Duration `json:"sampleEvery"`
	// Tick is the scheduler's grid: every run lands on a multiple of it from the start.
	Tick Duration `json:"tick"`
	// HeartbeatInterval is how often SITESCOPE_HEARTBEAT_URL is pinged.
	HeartbeatInterval Duration `json:"heartbeatInterval"`
	// LockedAfter is how long the vault may stay locked before hub.vault warns; negative disables.
	LockedAfter Duration `json:"lockedAfter"`
	Concurrency int      `json:"concurrency"`
}

type Agent struct {
	Listen      string `json:"listen"`
	WGInterface string `json:"wgInterface"`
	Postfix     bool   `json:"postfix"`
	Knot        bool   `json:"knot"`
	KnotSocket  string `json:"knotSocket"`
	// WireGuard is on unless set to false.
	WireGuard *bool `json:"wireguard,omitempty"`
	// WGPeers names peers in metric labels; hosts.wgPeers is used when this is empty.
	WGPeers map[string]string `json:"wgPeers"`
	// Command paths; the module fills these from nixpkgs.
	Systemctl string `json:"systemctl"`
	WG        string `json:"wg"`
	Postqueue string `json:"postqueue"`
	Knotc     string `json:"knotc"`
}

func (a Agent) WireGuardOn() bool { return a.WireGuard == nil || *a.WireGuard }

type Alerts struct {
	Enabled          bool     `json:"enabled"`
	SMTP             string   `json:"smtp"`
	From             string   `json:"from"`
	To               []string `json:"to"`
	SubjectPrefix    string   `json:"subjectPrefix"`
	RenotifyInterval Duration `json:"renotifyInterval"`
	// UnknownAfter alerts on a check stuck in unknown this long; negative disables.
	UnknownAfter Duration `json:"unknownAfter"`
	DigestTime   string   `json:"digestTime"`
}

// Public is one rule for the public page; each check takes the first rule that matches it.
type Public struct {
	Name   string   `json:"name"`
	Areas  []string `json:"areas"`
	Checks []string `json:"checks"` // check id globs
	// public: one row per check; grouped (default): one light; private: not on the public page.
	Visibility string            `json:"visibility"`
	Labels     map[string]string `json:"labels"` // check id -> public label
}

const (
	VisPublic  = "public"
	VisGrouped = "grouped"
	VisPrivate = "private"
)

func (p Public) Matches(id, area string) bool {
	if slices.Contains(p.Areas, area) {
		return true
	}
	for _, g := range p.Checks {
		if ok, _ := path.Match(g, id); ok {
			return true
		}
	}
	return false
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	return &c, c.validate()
}

func intp(i int) *int { return &i }

// Def sets *s to v when it is empty.
func Def(s *string, v string) {
	if *s == "" {
		*s = v
	}
}

func (c *Config) applyDefaults() {
	for i := range c.Public {
		if c.Public[i].Visibility == "" {
			c.Public[i].Visibility = VisGrouped
		}
	}
	c.Defaults = c.Defaults.Merge(Timing{
		Interval:      Duration(5 * time.Minute),
		Timeout:       Duration(10 * time.Second),
		Retries:       intp(2),
		RetryInterval: Duration(time.Minute),
	})
	h := &c.Hub
	def := Def
	def(&h.Listen, "127.0.0.1:8470")
	def(&h.StateDir, "/var/lib/sitescope")
	def(&h.ControlSocket, "/run/sitescope/control.sock")
	def(&h.Title, "Status")
	def(&h.Vault, h.StateDir+"/vault.age")
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}
	if h.Refresh == 0 {
		h.Refresh = 60
	}
	def(&h.DocsURL, "https://toppk.github.io/sitescope/")
	if h.RetentionDays == 0 {
		h.RetentionDays = 35
	}
	if h.Tick == 0 {
		h.Tick = Duration(time.Minute)
	}
	if h.LockedAfter == 0 {
		h.LockedAfter = Duration(15 * time.Minute)
	}
	if h.HeartbeatInterval == 0 {
		h.HeartbeatInterval = Duration(time.Minute)
	}
	if h.SampleEvery == 0 {
		h.SampleEvery = Duration(15 * time.Minute)
	}
	if h.Concurrency == 0 {
		h.Concurrency = 8
	}
	a := &c.Agent
	def(&a.WGInterface, "wg0")
	def(&a.KnotSocket, "/run/knot/knot.sock")
	def(&a.Systemctl, "systemctl")
	def(&a.WG, "wg")
	def(&a.Postqueue, "postqueue")
	def(&a.Knotc, "knotc")
	al := &c.Alerts
	def(&al.SMTP, "127.0.0.1:25")
	def(&al.SubjectPrefix, "[sitescope]")
	if al.RenotifyInterval == 0 {
		al.RenotifyInterval = Duration(time.Hour)
	}
	if al.UnknownAfter == 0 {
		al.UnknownAfter = Duration(time.Hour)
	}
	for _, sec := range c.sections {
		sec.Defaults(c)
	}
}

func (c *Config) validate() error {
	if a := c.Alerts; a.Enabled && (a.From == "" || len(a.To) == 0) {
		return fmt.Errorf("config: alerts.enabled needs alerts.from and alerts.to")
	}
	for i, p := range c.Public {
		switch p.Visibility {
		case VisPublic, VisGrouped, VisPrivate:
		default:
			return fmt.Errorf("config: public[%d].visibility %q, want public, grouped or private", i, p.Visibility)
		}
		if p.Name == "" && p.Visibility != VisPrivate {
			return fmt.Errorf("config: public[%d] needs a name", i)
		}
		if len(p.Areas) == 0 && len(p.Checks) == 0 {
			return fmt.Errorf("config: public[%d] needs areas or checks", i)
		}
		for _, g := range p.Checks {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("config: public[%d].checks %q: %w", i, g, err)
			}
		}
	}
	for _, sec := range c.sections {
		if err := sec.Validate(); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	if d := c.Alerts.DigestTime; d != "" {
		if _, _, err := ParseClock(d); err != nil {
			return err
		}
	}
	return nil
}

// ParseClock parses "HH:MM".
func ParseClock(s string) (int, int, error) {
	if len(s) == 5 && s[2] == ':' {
		h, err1 := strconv.Atoi(s[:2])
		m, err2 := strconv.Atoi(s[3:])
		if err1 == nil && err2 == nil && h < 24 && m < 60 {
			return h, m, nil
		}
	}
	return 0, 0, fmt.Errorf("config: bad time %q, want HH:MM", s)
}
