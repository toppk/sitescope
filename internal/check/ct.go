package check

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

// CTIssuance is one certificate from Cert Spotter's issuances API.
type CTIssuance struct {
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
	Issuer     struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

func (c CTIssuance) issuer() string {
	if c.Issuer.FriendlyName != "" {
		return c.Issuer.FriendlyName
	}
	return c.Issuer.Name
}

// ctSpacing keeps unauthenticated use within Cert Spotter's free rate limit.
const ctSpacing = 7 * time.Second

type ctAPI struct {
	base, secret string
	mu           sync.Mutex
	last         time.Time
}

func (a *ctAPI) wait(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d := ctSpacing - time.Since(a.last); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a.last = time.Now()
	return nil
}

func ctCheck(a *ctAPI, domain string, cfg *config.CT) func(context.Context, *Env) Result {
	allowed := append(slices.Clone(cfg.Issuers), cfg.DomainIssuers[domain]...)
	return func(ctx context.Context, env *Env) Result {
		if err := a.wait(ctx); err != nil {
			return Unknownf("%v", err)
		}
		q := url.Values{"domain": {domain}, "include_subdomains": {"true"}, "expand": {"dns_names", "issuer"}}
		hdr := map[string]string{}
		if env.Secret != nil {
			if tok, ok := env.Secret(a.secret); ok {
				hdr["Authorization"] = "Bearer " + tok
			}
		}
		var certs []CTIssuance
		err := getJSON(ctx, env, a.base+"/issuances?"+q.Encode(), hdr, &certs)
		if se, ok := err.(*httpStatusError); ok && se.code == 429 {
			return Unknownf("rate limited by Cert Spotter; will try again next round")
		}
		if err != nil {
			return Unknownf("Cert Spotter: %v", err)
		}
		return EvalCT(certs, allowed, cfg.Names, cfg.Ignore, env.now(), cfg.Recent.D())
	}
}

// EvalCT rates a domain's currently valid certificates: an issuer not allowed is critical,
// a name not expected is a warning, and recent issuances are listed.
func EvalCT(certs []CTIssuance, issuers, names, ignore []string, now time.Time, recent time.Duration) Result {
	ignored := func(c CTIssuance) bool {
		return slices.ContainsFunc(ignore, func(p string) bool { return p != "" && strings.HasPrefix(c.CertSHA256, p) })
	}
	expected := func(n string) bool {
		return slices.ContainsFunc(names, func(g string) bool { ok, _ := path.Match(g, n); return ok })
	}
	slices.SortFunc(certs, func(a, b CTIssuance) int { return b.NotBefore.Compare(a.NotBefore) })
	s := OK
	var problems, fresh []string
	byIssuer := map[string]int{}
	for _, c := range certs {
		iss := c.issuer()
		byIssuer[iss]++
		if ignored(c) {
			continue
		}
		id := fmt.Sprintf("%s (%s, issued %s, sha256 %.12s)", strings.Join(c.DNSNames, " "), iss,
			c.NotBefore.Format("2006-01-02"), c.CertSHA256)
		if !slices.ContainsFunc(issuers, func(a string) bool { return strings.Contains(c.Issuer.Name+" "+iss, a) }) {
			s = Crit
			problems = append(problems, "unexpected issuer: "+id)
			continue
		}
		if len(names) > 0 {
			var odd []string
			for _, n := range c.DNSNames {
				if !expected(n) {
					odd = append(odd, n)
				}
			}
			if len(odd) > 0 {
				s = Worst(s, Warn)
				problems = append(problems, "unexpected name "+strings.Join(odd, " ")+": "+id)
				continue
			}
		}
		if now.Sub(c.NotBefore) < recent {
			fresh = append(fresh, strings.Join(c.DNSNames, " ")+" ("+iss+", "+c.NotBefore.Format("01-02")+")")
		}
	}
	var counts []string
	for _, iss := range slices.SortedFunc(func(yield func(string) bool) {
		for k := range byIssuer {
			if !yield(k) {
				return
			}
		}
	}, func(a, b string) int { return cmp.Compare(byIssuer[b], byIssuer[a]) }) {
		counts = append(counts, fmt.Sprintf("%s %d", iss, byIssuer[iss]))
	}
	msg := fmt.Sprintf("%d valid certificates", len(certs))
	if len(certs) == 1 {
		msg = "1 valid certificate"
	}
	if len(counts) > 0 {
		msg += " (" + strings.Join(counts, ", ") + ")"
	}
	if len(problems) > 0 {
		msg = strings.Join(problems, "; ") + "; " + msg
	}
	if len(fresh) > 0 {
		msg += "; new in " + fmtDuration(recent) + ": " + strings.Join(fresh, ", ")
	}
	return Rated(s, "%s", msg)
}
