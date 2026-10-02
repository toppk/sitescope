package check

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func hostport(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

// exchange sends one query, retrying over TCP when the UDP answer is truncated.
func exchange(ctx context.Context, server string, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp"}
	m.SetEdns0(1232, false)
	r, _, err := c.ExchangeContext(ctx, m, hostport(server))
	if err == nil && r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, hostport(server))
	}
	return r, err
}

func query(ctx context.Context, server, name string, qtype uint16, recurse bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = recurse
	return exchange(ctx, server, m)
}

func soaSerial(r *dns.Msg) (uint32, bool) {
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

func primaryCheck(primary string, zones []string) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		var bad []string
		for _, z := range zones {
			r, err := query(ctx, primary, z, dns.TypeSOA, false)
			switch {
			case err != nil:
				bad = append(bad, fmt.Sprintf("%s: %v", z, err))
			case r.Rcode != dns.RcodeSuccess || !r.Authoritative:
				bad = append(bad, fmt.Sprintf("%s: %s aa=%v", z, dns.RcodeToString[r.Rcode], r.Authoritative))
			}
		}
		if len(bad) > 0 {
			return Critf("%s", strings.Join(bad, "; "))
		}
		return Okf("%d zones authoritative", len(zones))
	}
}

// serials caches the primary's SOA serial per zone briefly, so every secondary check
// in a round compares against one query instead of each asking again.
type serials struct {
	mu sync.Mutex
	m  map[string]serialAt
}

type serialAt struct {
	serial uint32
	at     time.Time
}

const serialTTL = time.Minute

func (s *serials) get(ctx context.Context, primary, zone string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[zone]; ok && time.Since(e.at) < serialTTL {
		return e.serial, nil
	}
	p, err := query(ctx, primary, zone, dns.TypeSOA, false)
	if err != nil {
		return 0, err
	}
	ps, ok := soaSerial(p)
	if !ok {
		return 0, fmt.Errorf("primary has no SOA")
	}
	if s.m == nil {
		s.m = map[string]serialAt{}
	}
	s.m[zone] = serialAt{ps, time.Now()}
	return ps, nil
}

func soaCheck(zone, server, primary string, ps *serials) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		r, err := query(ctx, server, zone, dns.TypeSOA, false)
		if err != nil {
			return Critf("no answer: %v", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			return Critf("rcode %s", dns.RcodeToString[r.Rcode])
		}
		if !r.Authoritative {
			return Critf("answer is not authoritative (aa flag missing)")
		}
		serial, ok := soaSerial(r)
		if !ok {
			return Critf("no SOA in answer")
		}
		if primary == "" {
			return Okf("serial %d", serial)
		}
		want, err := ps.get(ctx, primary, zone)
		if err != nil {
			return Okf("serial %d (primary: %v; not compared)", serial, err)
		}
		return CompareSerial(serial, want)
	}
}

func CompareSerial(secondary, primary uint32) Result {
	if secondary != primary {
		return Warnf("serial %d, primary has %d", secondary, primary)
	}
	return Okf("serial %d matches primary", secondary)
}

func nsNames(rrs []dns.RR, zone string) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && fqdn(ns.Hdr.Name) == zone {
			out = append(out, fqdn(ns.Ns))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// tldServers finds the parent zone's name servers through the public resolver.
func tldServers(ctx context.Context, zone, resolver string) ([]string, error) {
	_, parent, ok := strings.Cut(zone, ".")
	if !ok {
		return nil, fmt.Errorf("%s has no parent", zone)
	}
	r, err := query(ctx, resolver, parent, dns.TypeNS, true)
	if err != nil {
		return nil, err
	}
	names := nsNames(r.Answer, parent)
	if len(names) == 0 {
		return nil, fmt.Errorf("no NS for %s", parent)
	}
	return names, nil
}

func delegationCheck(zone string, want []string, resolver string) func(context.Context, *Env) Result {
	for i := range want {
		want[i] = fqdn(want[i])
	}
	slices.Sort(want)
	return func(ctx context.Context, _ *Env) Result {
		servers, err := tldServers(ctx, zone, resolver)
		if err != nil {
			return Critf("parent lookup: %v", err)
		}
		var lastErr error
		for _, s := range servers[:min(3, len(servers))] {
			a, err := query(ctx, resolver, s, dns.TypeA, true)
			if err != nil || len(a.Answer) == 0 {
				lastErr = fmt.Errorf("resolve %s: %v", s, err)
				continue
			}
			var ip string
			for _, rr := range a.Answer {
				if v, ok := rr.(*dns.A); ok {
					ip = v.A.String()
				}
			}
			r, err := query(ctx, ip, zone, dns.TypeNS, false)
			if err != nil {
				lastErr = err
				continue
			}
			got := nsNames(append(r.Ns, r.Answer...), zone)
			return CompareDelegation(got, want, s)
		}
		return Critf("no parent server answered: %v", lastErr)
	}
}

func CompareDelegation(got, want []string, server string) Result {
	var missing, extra []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, g)
		}
	}
	switch {
	case len(got) == 0:
		return Critf("%s returns no delegation", server)
	case len(missing) > 0:
		return Critf("%s delegates to %s; missing %s", server, strings.Join(got, " "), strings.Join(missing, " "))
	case len(extra) > 0:
		return Warnf("%s also delegates to %s", server, strings.Join(extra, " "))
	}
	return Okf("delegated to %s", strings.Join(got, " "))
}

func resolveCheck(name string, want []string, resolver string) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		var got []string
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r, err := query(ctx, resolver, name, qt, true)
			if err != nil {
				return Critf("%s lookup: %v", dns.TypeToString[qt], err)
			}
			for _, rr := range r.Answer {
				switch v := rr.(type) {
				case *dns.A:
					got = append(got, v.A.String())
				case *dns.AAAA:
					got = append(got, v.AAAA.String())
				}
			}
		}
		return CompareAddrs(got, want)
	}
}

func normIPs(in []string) []string {
	var out []string
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.String())
		} else {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func CompareAddrs(got, want []string) Result {
	g, w := normIPs(got), normIPs(want)
	if slices.Equal(g, w) {
		return Okf("%s", strings.Join(g, " "))
	}
	if len(g) == 0 {
		return Critf("does not resolve, want %s", strings.Join(w, " "))
	}
	return Critf("resolves to %s, want %s", strings.Join(g, " "), strings.Join(w, " "))
}
