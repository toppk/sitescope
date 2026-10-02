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

func bannerCheck(addr string, s config.MailServer, lat Threshold) func(context.Context, *Env) Result {
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

func openRelayCheck(addr string, port int, cfg *config.OpenRelay) func(context.Context, *Env) Result {
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

func blocklistCheck(ipStr string, cfg *config.Blocklists) func(context.Context, *Env) Result {
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
