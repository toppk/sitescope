package check

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

// Areas in display order, with the public name used when config.public is empty.
var Areas = []struct{ ID, Name string }{
	{"dns", "DNS"}, {"mail", "Mail"}, {"http", "Web"}, {"tls", "Certificates"},
	{"domains", "Domains"}, {"hosts", "Servers"}, {"hygiene", "Maintenance"}, {"cloud", "Hosting account"},
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
	b.hosts()
	b.dns()
	b.domains()
	b.tls()
	b.ct()
	b.http()
	b.mail()
	b.linode()
	b.cloudflare()
	return b.checks, nil
}

func (b *builder) dns() {
	d := b.cfg.DNS
	if d == nil {
		return
	}
	t := d.Timing
	ps := &serials{}
	if d.Primary != "" {
		b.add(t, &Check{ID: "dns.primary", Name: "Primary answers for all zones", Area: "dns", Group: "Primary",
			Probes: []Probe{{d.Primary, "53/udp", "SOA query per zone", len(d.Zones)}},
			Run:    primaryCheck(d.Primary, d.Zones)})
	}
	for _, z := range d.Zones {
		z = fqdn(z)
		for si, s := range d.Servers {
			for ai, a := range s.Addrs {
				p := []Probe{{a, "53/udp", "SOA query", 1}}
				// one serial query per zone per round; the cache serves the others
				if d.Primary != "" && si == 0 && ai == 0 {
					p = append(p, Probe{d.Primary, "53/udp", "SOA query (serial for the secondaries to match)", 1})
				}
				b.add(t, &Check{ID: fmt.Sprintf("dns.soa.%s.%s.%s", z, s.Name, family(a)),
					Name: fmt.Sprintf("SOA %s on %s (%s)", z, s.Name, family(a)), Area: "dns", Group: s.Name,
					Probes: p, Run: soaCheck(z, a, d.Primary, ps)})
			}
		}
		if len(d.Delegation) > 0 {
			b.add(config.Timing{Interval: config.Duration(time.Hour)}.Merge(t), &Check{
				ID: "dns.delegation." + z, Name: "TLD delegation " + z, Area: "dns", Group: "Delegation",
				Probes: []Probe{{d.PublicResolver, "53/udp", "recursive NS and A lookups", 2},
					{"a name server of the parent zone", "53/udp", "NS query", 1}},
				Run: delegationCheck(z, d.Delegation, d.PublicResolver)})
		}
	}
	for name, want := range d.Resolve {
		name = fqdn(name)
		b.add(t, &Check{ID: "dns.resolve." + name, Name: "Public resolution of " + name, Area: "dns", Group: "Resolution",
			Probes: []Probe{{d.PublicResolver, "53/udp", "recursive A and AAAA lookups", 2}},
			Run:    resolveCheck(name, want, d.PublicResolver)})
	}
}

func (b *builder) domains() {
	d := b.cfg.Domains
	if d == nil {
		return
	}
	t := d.Timing.Merge(config.Timing{Interval: config.Duration(12 * time.Hour), Timeout: config.Duration(30 * time.Second),
		RetryInterval: config.Duration(10 * time.Minute)})
	rd := &rdap{bootstrapURL: d.Bootstrap, overrides: d.Servers}
	for _, n := range d.Names {
		n = fqdn(n)
		tld := n[strings.LastIndex(n, ".")+1:]
		b.add(t, &Check{ID: "domain." + n, Name: "Registration of " + n, Area: "domains",
			Probes: []Probe{{"RDAP server for ." + tld, "443/tcp", "HTTPS GET domain record", 1}},
			Run:    rd.check(n, d.Days)})
	}
}

func (b *builder) tls() {
	c := b.cfg.TLS
	if c == nil {
		return
	}
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(6 * time.Hour)})
	for _, tg := range c.Targets {
		port := tg.Port
		if port == 0 {
			port = map[string]int{"smtp": 25}[tg.StartTLS]
			if port == 0 {
				port = 443
			}
		}
		fams := tg.Families
		if len(fams) == 0 {
			fams = []string{"4", "6"}
		}
		host := tg.Host
		if host == "" {
			host = tg.Name
		}
		name := tg.Name
		if name == "" {
			name = host
		}
		for _, f := range fams {
			proto := "https"
			if tg.StartTLS != "" {
				proto = tg.StartTLS
			}
			what := "TLS handshake"
			if tg.ALPN != "" {
				what += " offering ALPN " + tg.ALPN + " and http/1.1"
			}
			if tg.StartTLS != "" {
				what = "EHLO, STARTTLS, handshake, QUIT"
			}
			b.add(t, &Check{ID: fmt.Sprintf("tls.%s.%s.%d.v%s", name, proto, port, f),
				Name: fmt.Sprintf("Certificate %s (%s:%d, IPv%s)", name, proto, port, f), Area: "tls", Group: name,
				Probes: []Probe{{host + " (IPv" + f + ")", fmt.Sprintf("%d/tcp", port), what, 1}},
				Run:    tlsCheck(host, port, "tcp"+f, tg.StartTLS, tg.ALPN, c.Days)})
		}
	}
}

func (b *builder) ct() {
	c := b.cfg.CT
	if c == nil {
		return
	}
	// Cert Spotter allows 10 requests an hour without a key, so the domains share a day
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(24 * time.Hour), Timeout: config.Duration(30 * time.Second),
		RetryInterval: config.Duration(10 * time.Minute)})
	api := &ctAPI{base: strings.TrimSuffix(c.API, "/"), secret: c.TokenSecret}
	for _, d := range c.Domains {
		d = fqdn(d)
		b.add(t, &Check{ID: "ct." + d, Name: "CT log certificates for " + d, Area: "tls", Group: "CT logs", Spread: "certspotter",
			Probes: []Probe{urlProbe(c.API, "HTTPS GET currently valid certificates for the domain and its subdomains")},
			Run:    ctCheck(api, d, c)})
	}
}

func (b *builder) http() {
	c := b.cfg.HTTP
	if c == nil {
		return
	}
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(time.Minute)})
	for _, tg := range c.Targets {
		name := tg.Name
		if name == "" {
			name = tg.URL
		}
		b.add(tg.Timing.Merge(t), &Check{ID: "http." + name, Name: "HTTP " + tg.URL, Area: "http",
			Probes: []Probe{urlProbe(tg.URL, "GET, redirects not followed")},
			Run:    httpCheck(tg)})
	}
}

func (b *builder) mail() {
	m := b.cfg.Mail
	if m == nil {
		return
	}
	if bn := m.Banner; bn != nil {
		for _, s := range bn.Servers {
			for _, a := range s.Addrs {
				b.add(bn.Timing, &Check{ID: fmt.Sprintf("mail.banner.%s.%s", s.Name, family(a)),
					Name: fmt.Sprintf("SMTP banner %s (%s)", s.Name, family(a)), Area: "mail", Group: s.Name,
					Probes: []Probe{{a, fmt.Sprintf("%d/tcp", smtpPort(s.Port)), "connect, read banner, QUIT", 1}},
					Run:    bannerCheck(a, s, bn.Latency.Or(Threshold{Warn: 3, Crit: 10}))})
			}
		}
	}
	if r := m.OpenRelay; r != nil {
		t := r.Timing.Merge(config.Timing{Interval: config.Duration(24 * time.Hour), RetryInterval: config.Duration(5 * time.Minute)})
		for _, s := range r.Servers {
			for _, a := range s.Addrs {
				b.add(t, &Check{ID: fmt.Sprintf("mail.openrelay.%s.%s", s.Name, family(a)),
					Name: fmt.Sprintf("Open relay probe %s (%s)", s.Name, family(a)), Area: "mail", Group: s.Name,
					Probes: []Probe{{a, fmt.Sprintf("%d/tcp", smtpPort(s.Port)),
						"EHLO, MAIL FROM, RCPT TO an outside address (expects 554), QUIT", 1}},
					Run: openRelayCheck(a, s.Port, r)})
			}
		}
	}
	if bl := m.Blocklists; bl != nil {
		t := bl.Timing.Merge(config.Timing{Interval: config.Duration(time.Hour)})
		for _, ip := range bl.IPs {
			n := 0
			for _, l := range bl.Lists {
				if l.IPv6 || !strings.Contains(ip, ":") {
					n++
				}
			}
			b.add(t, &Check{ID: "mail.blocklist." + ip, Name: "Blocklists for " + ip, Area: "mail", Group: "Blocklists",
				Probes: []Probe{{bl.Resolver, "53/udp", "DNSBL lookup per list, forwarded to the lists by that resolver", n}},
				Run:    blocklistCheck(ip, bl)})
		}
	}
}

func (b *builder) linode() {
	l := b.cfg.Linode
	if l == nil {
		return
	}
	t := l.Timing.Merge(config.Timing{Interval: config.Duration(time.Hour), Timeout: config.Duration(30 * time.Second)})
	api := &linodeAPI{base: strings.TrimSuffix(l.API, "/"), secret: l.TokenSecret}
	add := func(id, name string, run func(context.Context, *Env) Result) {
		b.add(t, &Check{ID: id, Name: name, Area: "cloud", Group: "Linode", Secret: l.TokenSecret,
			Probes: []Probe{urlProbe(l.API, "HTTPS GET, read-only token")}, Run: run})
	}
	add("linode.account", "Linode account balance", api.account(l))
	add("linode.transfer", "Linode network transfer", api.transfer(l))
	add("linode.maintenance", "Linode maintenance and notices", api.maintenance())
	add("linode.events", "Linode recent events", api.events(l))
	for _, in := range l.Instances {
		add("linode.instance."+in.Name, "Linode instance "+in.Name, api.instance(in))
	}
}

func (b *builder) cloudflare() {
	c := b.cfg.Cloudflare
	if c == nil {
		return
	}
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(time.Hour), Timeout: config.Duration(30 * time.Second)})
	p := urlProbe(c.API, "HTTPS GET DNS records, read-only token")
	if c.ZoneID == "" {
		p.What, p.Count = "HTTPS GET zone by name, then its DNS records, read-only token", 2
	}
	b.add(t, &Check{ID: "cloudflare.records." + fqdn(c.Zone), Name: "Cloudflare records for " + c.Zone,
		Area: "cloud", Group: "Cloudflare", Secret: c.TokenSecret, Probes: []Probe{p}, Run: cloudflareCheck(c)})
}
