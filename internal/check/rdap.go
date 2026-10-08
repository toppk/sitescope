package check

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

type Domains struct {
	config.Timing
	Names     []string  `json:"names"`
	Days      Threshold `json:"days"`
	Bootstrap string    `json:"bootstrap"`
	// RDAP base URLs per TLD, used before the IANA bootstrap file.
	Servers map[string]string `json:"servers"`
}

func (d *Domains) Defaults(*config.Config) {
	d.Days = d.Days.Or(Threshold{Warn: 45, Crit: 14})
	config.Def(&d.Bootstrap, "https://data.iana.org/rdap/dns.json")
}

func (d *Domains) Validate() error { return nil }

func (d *Domains) build(b *builder) {
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

// fallbackRDAP covers registries that run RDAP but are missing from the IANA bootstrap file.
var fallbackRDAP = map[string]string{
	"us": "https://rdap.nic.us/",
	"co": "https://rdap.registry.co/co/",
}

type rdap struct {
	bootstrapURL string
	overrides    map[string]string

	mu      sync.Mutex
	servers map[string]string
	fetched time.Time
}

func getJSON(ctx context.Context, env *Env, url string, hdr map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 4<<20)
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, body)
		e := &httpStatusError{code: resp.StatusCode}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			e.retryAfter = time.Duration(s) * time.Second
		}
		return e
	}
	return json.NewDecoder(body).Decode(v)
}

type httpStatusError struct {
	code       int
	retryAfter time.Duration
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// server returns the RDAP base URL for a TLD from the IANA bootstrap file, cached for a day.
func (r *rdap) server(ctx context.Context, env *Env, tld string) (string, error) {
	if base, ok := r.overrides[tld]; ok {
		return base, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.servers == nil || time.Since(r.fetched) > 24*time.Hour {
		var boot struct {
			Services [][][]string `json:"services"`
		}
		if err := getJSON(ctx, env, r.bootstrapURL, nil, &boot); err != nil {
			if r.servers == nil {
				return "", fmt.Errorf("RDAP bootstrap: %w", err)
			}
		} else {
			r.servers, r.fetched = map[string]string{}, time.Now()
			for _, s := range boot.Services {
				if len(s) == 2 && len(s[1]) > 0 {
					for _, t := range s[0] {
						r.servers[strings.ToLower(t)] = s[1][0]
					}
				}
			}
		}
	}
	base, ok := r.servers[tld]
	if !ok {
		base, ok = fallbackRDAP[tld]
	}
	if !ok {
		return "", fmt.Errorf("no RDAP server for .%s", tld)
	}
	return base, nil
}

type rdapDomain struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Status []string `json:"status"`
}

// Expiry reads the expiration event; some registries (.si) give only a date.
func (d *rdapDomain) Expiry() (time.Time, error) {
	for _, e := range d.Events {
		if e.Action != "expiration" {
			continue
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, e.Date); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("RDAP expiration date %q not understood", e.Date)
	}
	return time.Time{}, fmt.Errorf("RDAP response has no expiration event")
}

func (r *rdap) check(name string, days Threshold) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		tld := name[strings.LastIndex(name, ".")+1:]
		base, err := r.server(ctx, env, tld)
		if err != nil {
			return Unknownf("%v", err)
		}
		var d rdapDomain
		err = getJSON(ctx, env, strings.TrimSuffix(base, "/")+"/domain/"+name,
			map[string]string{"Accept": "application/rdap+json"}, &d)
		if se, ok := err.(*httpStatusError); ok && se.code == 404 {
			return Critf("registry says %s is not registered", name)
		}
		if err != nil {
			r := Unknownf("RDAP: %v", err)
			r.RetryIn = time.Hour // a registry hiccup shouldn't cost a 12h interval
			return r
		}
		exp, err := d.Expiry()
		if err != nil {
			return Unknownf("%v", err)
		}
		return EvalExpiry(exp, env.now(), days, "registration")
	}
}

// EvalExpiry rates the days left until t.
func EvalExpiry(t, now time.Time, days Threshold, what string) Result {
	left := t.Sub(now).Hours() / 24
	if left < 0 {
		return Critf("%s expired %s", what, t.Format("2006-01-02"))
	}
	return Rated(days.Below(left), "%s expires %s (%d days)", what, t.Format("2006-01-02"), int(left))
}
