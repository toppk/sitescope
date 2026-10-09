package check

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/toppk/sitescope/internal/config"
)

// Areas in display order, with the public name used when config.public is empty.
var Areas = []struct{ ID, Name string }{
	{"dns", "DNS"}, {"mail", "Mail"}, {"http", "Web"}, {"tls", "Certificates"},
	{"domains", "Domains"}, {"hosts", "Servers"}, {"devices", "Devices"}, {"hygiene", "Maintenance"}, {"cloud", "Hosting account"},
	{"hub", "Monitoring"},
}

// module is a config section that expands into checks.
type module interface {
	config.Section
	build(b *builder)
}

// Modules are registered in build order, which is the order checks appear in.
func init() {
	config.Register("hosts", func() config.Section { return new(Hosts) })
	config.Register("dns", func() config.Section { return new(DNS) })
	config.Register("domains", func() config.Section { return new(Domains) })
	config.Register("tls", func() config.Section { return new(TLS) })
	config.Register("ct", func() config.Section { return new(CT) })
	config.Register("http", func() config.Section { return new(HTTP) })
	config.Register("mail", func() config.Section { return new(Mail) })
	config.Register("ping", func() config.Section { return new(Ping) })
	config.Register("tcp", func() config.Section { return new(TCP) })
	config.Register("ipp", func() config.Section { return new(IPP) })
	config.Register("linode", func() config.Section { return new(Linode) })
	config.Register("cloudflare", func() config.Section { return new(Cloudflare) })
}

type builder struct {
	cfg    *config.Config
	checks []*Check
	seen   map[string]bool
}

func (b *builder) add(t config.Timing, c *Check) {
	t = t.Merge(b.cfg.Defaults)
	c.Interval, c.Timeout, c.RetryInterval = t.Interval.D(), t.Timeout.D(), t.RetryInterval.D()
	c.Retries = *t.Retries
	if c.Timeout > c.Interval {
		c.Timeout = c.Interval
	}
	if b.seen[c.ID] {
		panic("duplicate check id " + c.ID)
	}
	b.seen[c.ID] = true
	b.checks = append(b.checks, c)
}

func family(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "v6"
	}
	return "v4"
}

func fqdn(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

func smtpPort(p int) int {
	if p == 0 {
		return 25
	}
	return p
}

func urlProbe(raw, what string) Probe {
	u, err := url.Parse(raw)
	if err != nil {
		return Probe{raw, "", what, 1}
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return Probe{u.Hostname(), port + "/tcp", what, 1}
}

// Build expands the config sections into individual checks.
func Build(cfg *config.Config) (checks []*Check, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("config: %v", r)
		}
	}()
	b := &builder{cfg: cfg, seen: map[string]bool{}}
	for _, s := range cfg.Sections() {
		if m, ok := s.(module); ok {
			m.build(b)
		}
	}
	return b.checks, nil
}
