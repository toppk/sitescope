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
)

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

func (d *rdapDomain) Expiry() (time.Time, bool) {
	for _, e := range d.Events {
		if e.Action == "expiration" {
			if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
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
			return Unknownf("RDAP: %v", err)
		}
		exp, ok := d.Expiry()
		if !ok {
			return Unknownf("RDAP response has no expiration event")
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
