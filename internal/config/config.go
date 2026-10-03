// Package config loads the JSON config written by the NixOS module.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"time"

	"github.com/toppk/sitescope/internal/status"
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

	Hosts      *Hosts      `json:"hosts"`
	DNS        *DNS        `json:"dns"`
	Domains    *Domains    `json:"domains"`
	TLS        *TLS        `json:"tls"`
	CT         *CT         `json:"ct"`
	HTTP       *HTTP       `json:"http"`
	Mail       *Mail       `json:"mail"`
	Linode     *Linode     `json:"linode"`
	Cloudflare *Cloudflare `json:"cloudflare"`
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
	// WGPeers names peers in metric labels; hosts.wgPeers is used when this is empty.
	WGPeers map[string]string `json:"wgPeers"`
	// Command paths; the module fills these from nixpkgs.
	Systemctl string `json:"systemctl"`
	WG        string `json:"wg"`
	Postqueue string `json:"postqueue"`
	Knotc     string `json:"knotc"`
}

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

type Hosts struct {
	Timing
	Hosts       []Host            `json:"hosts"`
	WGPeers     map[string]string `json:"wgPeers"`
	Disk        status.Threshold  `json:"disk"`
	Memory      status.Threshold  `json:"memory"`
	Swap        status.Threshold  `json:"swap"`
	Load        status.Threshold  `json:"load"`
	WGHandshake status.Threshold  `json:"wgHandshake"`
	QueueSize   status.Threshold  `json:"queueSize"`
	QueueAge    status.Threshold  `json:"queueAge"`
	KnotExpiry  status.Threshold  `json:"knotExpiry"`
	NixpkgsAge  status.Threshold  `json:"nixpkgsAge"`
	// Rates are computed over RateWindow from the agents' counters.
	RateWindow  Duration         `json:"rateWindow"`
	CPU         status.Threshold `json:"cpu"`         // percent busy
	MemoryStall status.Threshold `json:"memoryStall"` // percent of time some task waited on memory
	SwapIn      status.Threshold `json:"swapIn"`      // pages per second
	DiskBusy    status.Threshold `json:"diskBusy"`    // percent of time a device was busy
	IOStall     status.Threshold `json:"ioStall"`     // percent of time some task waited on I/O
	NetErrors   status.Threshold `json:"netErrors"`   // errors and drops per second
	NetMbps     status.Threshold `json:"netMbps"`     // off unless set
	UnitMemory  status.Threshold `json:"unitMemory"`  // percent of a service's MemoryMax
	KnotZones   []string         `json:"knotZones"`
}

type Host struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Postfix bool   `json:"postfix"`
	Knot    bool   `json:"knot"`
	// WireGuard peers to ignore (by name or key), e.g. a roaming peer that may sleep.
	WGIgnore []string `json:"wgIgnore"`
}

type DNS struct {
	Timing
	Zones           []string            `json:"zones"`
	Primary         string              `json:"primary"`
	Servers         []NameServer        `json:"servers"`
	Delegation      []string            `json:"delegation"`
	DelegationZones []string            `json:"delegationZones"`
	PublicResolver  string              `json:"publicResolver"`
	Resolve         map[string][]string `json:"resolve"`
}

type NameServer struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

type Domains struct {
	Timing
	Names     []string         `json:"names"`
	Days      status.Threshold `json:"days"`
	Bootstrap string           `json:"bootstrap"`
	// RDAP base URLs per TLD, used before the IANA bootstrap file.
	Servers map[string]string `json:"servers"`
}

// CT watches Certificate Transparency logs (through Cert Spotter) for certificates on our domains.
type CT struct {
	Timing
	Domains []string `json:"domains"` // default domains.names
	Issuers []string `json:"issuers"` // allowed issuers, matched as substrings of the issuer
	// DomainIssuers adds issuers for one domain, e.g. a CDN's CAs.
	DomainIssuers map[string][]string `json:"domainIssuers"`
	Names         []string            `json:"names"`  // expected DNS names (globs); empty skips the name check
	Ignore        []string            `json:"ignore"` // certificate SHA-256s, or prefixes, already looked at
	Recent        Duration            `json:"recent"` // certificates this new are listed in the message
	API           string              `json:"api"`
	TokenSecret   string              `json:"tokenSecret"` // optional Cert Spotter API key in the vault
}

type TLS struct {
	Timing
	Targets []TLSTarget      `json:"targets"`
	Days    status.Threshold `json:"days"`
}

type TLSTarget struct {
	Name     string   `json:"name"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	StartTLS string   `json:"starttls"`
	Families []string `json:"families"`
	ALPN     string   `json:"alpn"` // protocol the server must choose, e.g. "h2"
}

type HTTP struct {
	Timing
	Targets []HTTPTarget `json:"targets"`
}

type HTTPTarget struct {
	Name         string           `json:"name"`
	URL          string           `json:"url"`
	ExpectStatus int              `json:"expectStatus"`
	Latency      status.Threshold `json:"latency"`
	Timing
}

type Mail struct {
	Banner     *MailBanner `json:"banner"`
	OpenRelay  *OpenRelay  `json:"openRelay"`
	Blocklists *Blocklists `json:"blocklists"`
}

type MailServer struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Port   int      `json:"port"`
	Expect string   `json:"expect"`
}

type MailBanner struct {
	Timing
	Servers []MailServer     `json:"servers"`
	Latency status.Threshold `json:"latency"`
}

type OpenRelay struct {
	Timing
	Servers []MailServer `json:"servers"`
	Helo    string       `json:"helo"`
	From    string       `json:"from"`
	To      string       `json:"to"`
	Expect  int          `json:"expect"`
}

type Blocklists struct {
	Timing
	Resolver string      `json:"resolver"`
	IPs      []string    `json:"ips"`
	Lists    []Blocklist `json:"lists"`
}

type Blocklist struct {
	Zone string `json:"zone"`
	IPv6 bool   `json:"ipv6"`
	Crit bool   `json:"crit"`
}

type Linode struct {
	Timing
	TokenSecret string           `json:"tokenSecret"`
	API         string           `json:"api"`
	Instances   []LinodeInstance `json:"instances"`
	Uninvoiced  status.Threshold `json:"uninvoiced"`
	Transfer    status.Threshold `json:"transfer"`
	EventWindow Duration         `json:"eventWindow"`
}

type LinodeInstance struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

type Cloudflare struct {
	Timing
	TokenSecret string      `json:"tokenSecret"`
	API         string      `json:"api"`
	Zone        string      `json:"zone"`
	ZoneID      string      `json:"zoneId"`
	AccountID   string      `json:"accountId"` // narrows the zone lookup when the token sees several accounts
	Expected    []DNSRecord `json:"expected"`
	// Extra name/type pairs where any record not in Expected counts as drift.
	Watch []DNSRecord `json:"watch"`
	// Tokens names the API tokens to watch for expiry; empty watches every active one.
	Tokens    []string         `json:"tokens"`
	TokenDays status.Threshold `json:"tokenDays"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority *int   `json:"priority,omitempty"`
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
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
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
	if c.Domains != nil {
		c.Domains.Days = c.Domains.Days.Or(status.Threshold{Warn: 45, Crit: 14})
		def(&c.Domains.Bootstrap, "https://data.iana.org/rdap/dns.json")
	}
	if c.TLS != nil {
		c.TLS.Days = c.TLS.Days.Or(status.Threshold{Warn: 20, Crit: 7})
	}
	if ct := c.CT; ct != nil {
		if len(ct.Domains) == 0 && c.Domains != nil {
			ct.Domains = c.Domains.Names
		}
		if len(ct.Issuers) == 0 {
			ct.Issuers = []string{"Let's Encrypt"}
		}
		if ct.Recent == 0 {
			ct.Recent = Duration(7 * 24 * time.Hour)
		}
		def(&ct.API, "https://api.certspotter.com/v1")
		def(&ct.TokenSecret, "certspotter_token")
	}
	if c.DNS != nil {
		def(&c.DNS.PublicResolver, "1.1.1.1")
	}
	if c.Mail != nil {
		if r := c.Mail.OpenRelay; r != nil {
			if r.Expect == 0 {
				r.Expect = 554
			}
			def(&r.Helo, h.Hostname)
			def(&r.From, "relay-probe@example.com")
			def(&r.To, "relay-probe@example.net")
		}
		if b := c.Mail.Blocklists; b != nil {
			def(&b.Resolver, "127.0.0.1:53")
		}
	}
	if c.Linode != nil {
		def(&c.Linode.TokenSecret, "linode_token")
		def(&c.Linode.API, "https://api.linode.com/v4")
		c.Linode.Transfer = c.Linode.Transfer.Or(status.Threshold{Warn: 80, Crit: 95})
		if c.Linode.EventWindow == 0 {
			c.Linode.EventWindow = Duration(24 * time.Hour)
		}
	}
	if c.Cloudflare != nil {
		def(&c.Cloudflare.TokenSecret, "cloudflare_token")
		def(&c.Cloudflare.API, "https://api.cloudflare.com/client/v4")
		c.Cloudflare.TokenDays = c.Cloudflare.TokenDays.Or(status.Threshold{Warn: 30, Crit: 7})
	}
	if hs := c.Hosts; hs != nil {
		hs.Disk = hs.Disk.Or(status.Threshold{Warn: 80, Crit: 90})
		hs.Memory = hs.Memory.Or(status.Threshold{Warn: 90, Crit: 97})
		hs.Swap = hs.Swap.Or(status.Threshold{Warn: 60, Crit: 90})
		hs.Load = hs.Load.Or(status.Threshold{Warn: 2, Crit: 4})
		hs.WGHandshake = hs.WGHandshake.Or(status.Threshold{Warn: 600, Crit: 3600})
		hs.QueueSize = hs.QueueSize.Or(status.Threshold{Warn: 20, Crit: 200})
		hs.QueueAge = hs.QueueAge.Or(status.Threshold{Warn: 3600, Crit: 4 * 3600})
		hs.KnotExpiry = hs.KnotExpiry.Or(status.Threshold{Warn: 14 * 86400, Crit: 3 * 86400})
		hs.NixpkgsAge = hs.NixpkgsAge.Or(status.Threshold{Warn: 30, Crit: 90})
		if hs.RateWindow == 0 {
			hs.RateWindow = Duration(5 * time.Minute)
		}
		hs.CPU = hs.CPU.Or(status.Threshold{Warn: 85, Crit: 95})
		hs.MemoryStall = hs.MemoryStall.Or(status.Threshold{Warn: 10, Crit: 30})
		hs.SwapIn = hs.SwapIn.Or(status.Threshold{Warn: 100, Crit: 1000})
		hs.DiskBusy = hs.DiskBusy.Or(status.Threshold{Warn: 80, Crit: 95})
		hs.IOStall = hs.IOStall.Or(status.Threshold{Warn: 25, Crit: 50})
		hs.NetErrors = hs.NetErrors.Or(status.Threshold{Warn: 1, Crit: 10})
		hs.UnitMemory = hs.UnitMemory.Or(status.Threshold{Warn: 85, Crit: 95})
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
	if c.CT != nil {
		for _, g := range c.CT.Names {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("config: ct.names %q: %w", g, err)
			}
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
