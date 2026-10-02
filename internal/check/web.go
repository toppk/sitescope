package check

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

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

func httpCheck(t config.HTTPTarget) func(context.Context, *Env) Result {
	want := t.ExpectStatus
	if want == 0 {
		want = 200
	}
	lat := t.Latency.Or(Threshold{Warn: 2, Crit: 5})
	return func(ctx context.Context, env *Env) Result {
		req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
		if err != nil {
			return Critf("%v", err)
		}
		req.Header.Set("User-Agent", userAgent)
		start := time.Now()
		resp, err := noRedirect(env.HTTP).Do(req)
		if err != nil {
			return Critf("%v", err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		took := time.Since(start)
		if resp.StatusCode != want {
			return Critf("status %d, want %d (%dms)", resp.StatusCode, want, took.Milliseconds())
		}
		return Rated(lat.Above(took.Seconds()), "status %d in %dms", resp.StatusCode, took.Milliseconds())
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
