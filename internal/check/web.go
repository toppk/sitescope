package check

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

type TLS struct {
	config.Timing
	Targets []TLSTarget `json:"targets"`
	Days    Threshold   `json:"days"`
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
	config.Timing
	Targets []HTTPTarget `json:"targets"`
}

type HTTPTarget struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	ExpectStatus int       `json:"expectStatus"`
	Latency      Threshold `json:"latency"`
	// CA is a PEM file of the only CA trusted for this URL, e.g. a device's own self-signed certificate.
	CA string `json:"ca,omitempty"`
	// Body is text the response must contain.
	Body string `json:"body,omitempty"`
	// Redirect is where the response must redirect to; any 3xx status then passes.
	Redirect string `json:"redirect,omitempty"`
	config.Timing
}

func (c *TLS) Defaults(*config.Config) { c.Days = c.Days.Or(Threshold{Warn: 20, Crit: 7}) }

func (c *TLS) Validate() error { return nil }

func (c *HTTP) Defaults(*config.Config) {}

func (c *HTTP) Validate() error {
	for _, t := range c.Targets {
		if t.Redirect == "" {
			continue
		}
		if _, err := url.Parse(t.Redirect); err != nil {
			return fmt.Errorf("http: %s redirect: %w", t.URL, err)
		}
	}
	return nil
}

func (c *TLS) build(b *builder) {
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

func (c *HTTP) build(b *builder) {
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

func tlsCheck(host string, port int, network, starttls, alpn string, days Threshold) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return Critf("connect: %v", err)
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl)
		}
		cfg := &tls.Config{ServerName: host}
		if alpn != "" && starttls == "" {
			cfg.NextProtos = []string{alpn, "http/1.1"}
		}
		var state tls.ConnectionState
		switch starttls {
		case "":
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				return Critf("TLS: %v", err)
			}
			state = tc.ConnectionState()
		case "smtp":
			c, err := smtp.NewClient(conn, host)
			if err != nil {
				return Critf("SMTP: %v", err)
			}
			if err := c.Hello(env.Hostname); err != nil {
				return Critf("EHLO: %v", err)
			}
			if err := c.StartTLS(cfg); err != nil {
				return Critf("STARTTLS: %v", err)
			}
			state, _ = c.TLSConnectionState()
			c.Quit()
		default:
			return Unknownf("unsupported starttls %q", starttls)
		}
		if len(state.PeerCertificates) == 0 {
			return Critf("no certificate")
		}
		leaf := state.PeerCertificates[0]
		r := EvalExpiry(leaf.NotAfter, env.now(), days, "certificate")
		r.Message += ", issuer " + leaf.Issuer.CommonName
		if len(cfg.NextProtos) > 0 {
			r = EvalALPN(r, alpn, state.NegotiatedProtocol)
		}
		return r
	}
}

func httpCheck(t HTTPTarget) func(context.Context, *Env) Result {
	want := t.ExpectStatus
	if want == 0 && t.Redirect == "" {
		want = 200
	}
	lat := t.Latency.Or(Threshold{Warn: 2, Crit: 5})
	client := caClient(t.CA)
	return func(ctx context.Context, env *Env) Result {
		c, err := client(env)
		if err != nil {
			return Critf("CA: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
		if err != nil {
			return Critf("%v", err)
		}
		req.Header.Set("User-Agent", userAgent)
		start := time.Now()
		resp, err := noRedirect(c).Do(req)
		if err != nil {
			return Critf("%v", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		took := time.Since(start)
		code, ms := resp.StatusCode, took.Milliseconds()
		if want != 0 && code != want {
			return Critf("status %d, want %d (%dms)", code, want, ms)
		}
		msg := fmt.Sprintf("status %d", code)
		if t.Redirect != "" {
			if code < 300 || code > 399 {
				return Critf("status %d, want a redirect to %s (%dms)", code, t.Redirect, ms)
			}
			loc, err := resp.Location()
			exp, _ := req.URL.Parse(t.Redirect)
			if err != nil || loc.String() != exp.String() {
				return Critf("redirects to %q, want %s (%dms)", resp.Header.Get("Location"), exp, ms)
			}
			msg += " to " + loc.String()
		}
		if t.Body != "" {
			if !bytes.Contains(body, []byte(t.Body)) {
				return Critf("%s, body lacks %q (%dms)", msg, t.Body, ms)
			}
			msg += ", body matches"
		}
		return Rated(lat.Above(took.Seconds()), "%s in %dms", msg, ms)
	}
}

func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// EvalALPN adds the negotiated protocol to r, warning when it isn't the one wanted.
func EvalALPN(r Result, want, got string) Result {
	if got == "" {
		got = "none"
	}
	r.Message += ", ALPN " + got
	if got != want {
		r.Status = Worst(r.Status, Warn)
		r.Message += " (want " + want + ")"
	}
	return r
}
