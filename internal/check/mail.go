package check

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/toppk/sitescope/internal/config"
)

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
	config.Timing
	Servers []MailServer `json:"servers"`
	Latency Threshold    `json:"latency"`
}

type OpenRelay struct {
	config.Timing
	Servers []MailServer `json:"servers"`
	Helo    string       `json:"helo"`
	From    string       `json:"from"`
	To      string       `json:"to"`
	Expect  int          `json:"expect"`
}

type Blocklists struct {
	config.Timing
	Resolver string      `json:"resolver"`
	IPs      []string    `json:"ips"`
	Lists    []Blocklist `json:"lists"`
}

type Blocklist struct {
	Zone string `json:"zone"`
	IPv6 bool   `json:"ipv6"`
	Crit bool   `json:"crit"`
}

func (m *Mail) Defaults(c *config.Config) {
	if r := m.OpenRelay; r != nil {
		if r.Expect == 0 {
			r.Expect = 554
		}
		config.Def(&r.Helo, c.Hub.Hostname)
		config.Def(&r.From, "relay-probe@example.com")
		config.Def(&r.To, "relay-probe@example.net")
	}
	if b := m.Blocklists; b != nil {
		config.Def(&b.Resolver, "127.0.0.1:53")
	}
}

func (m *Mail) Validate() error { return nil }

func (m *Mail) build(b *builder) {
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

func smtpDial(ctx context.Context, addr string, port int) (*textproto.Conn, error) {
	if port == 0 {
		port = 25
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	return textproto.NewConn(conn), nil
}

// quit ends the session politely, so the server logs a QUIT rather than a lost connection.
func quit(c *textproto.Conn) {
	if c.PrintfLine("QUIT") == nil {
		c.ReadResponse(221)
	}
}

func bannerCheck(addr string, s MailServer, lat Threshold) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		start := time.Now()
		c, err := smtpDial(ctx, addr, s.Port)
		if err != nil {
			return Critf("connect: %v", err)
		}
		defer c.Close()
		_, msg, err := c.ReadResponse(220)
		took := time.Since(start)
		if err != nil {
			return Critf("banner: %v", err)
		}
		quit(c)
		if s.Expect != "" && !strings.Contains(msg, s.Expect) {
			return Warnf("banner %q does not mention %s", msg, s.Expect)
		}
		return Rated(lat.Above(took.Seconds()), "220 %s (%dms)", msg, took.Milliseconds())
	}
}

func openRelayCheck(addr string, port int, cfg *OpenRelay) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		c, err := smtpDial(ctx, addr, port)
		if err != nil {
			return Critf("connect: %v", err)
		}
		defer c.Close()
		step := func(expect int, f string, a ...any) (int, string, error) {
			if f != "" {
				if err := c.PrintfLine(f, a...); err != nil {
					return 0, "", err
				}
			}
			return c.ReadResponse(expect)
		}
		if _, _, err := step(220, ""); err != nil {
			return Critf("banner: %v", err)
		}
		if _, _, err := step(250, "EHLO %s", cfg.Helo); err != nil {
			return Critf("EHLO: %v", err)
		}
		if _, _, err := step(250, "MAIL FROM:<%s>", cfg.From); err != nil {
			return Warnf("MAIL FROM rejected, relay not tested: %v", err)
		}
		code, msg, _ := step(0, "RCPT TO:<%s>", cfg.To)
		quit(c)
		return EvalRelay(code, msg, cfg.Expect)
	}
}

// EvalRelay rates the reply to RCPT TO for a foreign domain.
func EvalRelay(code int, msg string, expect int) Result {
	switch {
	case code == expect:
		return Okf("relaying refused: %d %s", code, msg)
	case code >= 200 && code < 400:
		return Critf("OPEN RELAY: RCPT accepted with %d %s", code, msg)
	case code == 0:
		return Critf("no reply to RCPT: %s", msg)
	}
	return Warnf("relaying refused with %d (expected %d): %s", code, expect, msg)
}

// ReverseName builds the DNSBL query name for an IP (nibbles for IPv6).
func ReverseName(ip netip.Addr, zone string) string {
	var parts []string
	if ip.Is4() {
		b := ip.As4()
		for i := 3; i >= 0; i-- {
			parts = append(parts, strconv.Itoa(int(b[i])))
		}
	} else {
		b := ip.As16()
		for i := 15; i >= 0; i-- {
			parts = append(parts, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
		}
	}
	return strings.Join(parts, ".") + "." + dns.Fqdn(zone)
}

// listed interprets DNSBL answers: 127.0.0.x means listed, 127.255.255.x is a refusal or error.
func listed(answers []string) (bool, error) {
	for _, a := range answers {
		if strings.HasPrefix(a, "127.255.255.") {
			return false, fmt.Errorf("list refused the query (%s)", a)
		}
	}
	for _, a := range answers {
		if strings.HasPrefix(a, "127.") {
			return true, nil
		}
	}
	return false, nil
}

func blocklistCheck(ipStr string, cfg *Blocklists) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return Unknownf("bad IP %q", ipStr)
		}
		worst, on, errs, asked := OK, []string{}, []string{}, 0
		for _, bl := range cfg.Lists {
			if ip.Is6() && !bl.IPv6 {
				continue
			}
			asked++
			r, err := query(ctx, cfg.Resolver, ReverseName(ip, bl.Zone), dns.TypeA, true)
			if err != nil {
				errs = append(errs, bl.Zone+": "+err.Error())
				continue
			}
			if r.Rcode == dns.RcodeNameError {
				continue
			}
			var ans []string
			for _, rr := range r.Answer {
				if a, ok := rr.(*dns.A); ok {
					ans = append(ans, a.A.String())
				}
			}
			hit, err := listed(ans)
			if err != nil {
				errs = append(errs, bl.Zone+": "+err.Error())
				continue
			}
			if hit {
				on = append(on, fmt.Sprintf("%s (%s)", bl.Zone, strings.Join(ans, ",")))
				if bl.Crit {
					worst = Crit
				} else {
					worst = Worst(worst, Warn)
				}
			}
		}
		switch {
		case len(on) > 0:
			return Rated(worst, "listed on %s", strings.Join(on, ", "))
		case asked > 0 && len(errs) == asked:
			return Unknownf("no list answered: %s", strings.Join(errs, "; "))
		case len(errs) > 0:
			return Okf("not listed on %d lists; errors: %s", asked-len(errs), strings.Join(errs, "; "))
		}
		return Okf("not listed on %d lists", asked)
	}
}
