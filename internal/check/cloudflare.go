package check

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

type Cloudflare struct {
	config.Timing
	TokenSecret string      `json:"tokenSecret"`
	API         string      `json:"api"`
	Zone        string      `json:"zone"`
	ZoneID      string      `json:"zoneId"`
	AccountID   string      `json:"accountId"` // narrows the zone lookup when the token sees several accounts
	Expected    []DNSRecord `json:"expected"`
	// Extra name/type pairs where any record not in Expected counts as drift.
	Watch []DNSRecord `json:"watch"`
	// Tokens names the API tokens to watch for expiry; empty watches every active one.
	Tokens    []string  `json:"tokens"`
	TokenDays Threshold `json:"tokenDays"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority *int   `json:"priority,omitempty"`
}

func (c *Cloudflare) Defaults(*config.Config) {
	config.Def(&c.TokenSecret, "cloudflare_token")
	config.Def(&c.API, "https://api.cloudflare.com/client/v4")
	c.TokenDays = c.TokenDays.Or(Threshold{Warn: 30, Crit: 7})
}

func (c *Cloudflare) Validate() error { return nil }

func (c *Cloudflare) build(b *builder) {
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(time.Hour), Timeout: config.Duration(30 * time.Second)})
	p := urlProbe(c.API, "HTTPS GET DNS records, read-only token")
	if c.ZoneID == "" {
		p.What, p.Count = "HTTPS GET zone by name, then its DNS records, read-only token", 2
	}
	b.add(t, &Check{ID: "cloudflare.records." + fqdn(c.Zone), Name: "Cloudflare records for " + c.Zone,
		Area: "cloud", Group: "Cloudflare", Secret: c.TokenSecret, Probes: []Probe{p}, Run: cloudflareCheck(c)})
	daily := t
	daily.Interval = config.Duration(24 * time.Hour)
	tp := urlProbe(c.API, "HTTPS GET verify this token, then list API tokens (names and expiry only)")
	if tp.Count = 2; c.AccountID != "" {
		tp.Count = 4
	}
	b.add(daily, &Check{ID: "cloudflare.tokens", Name: "Cloudflare API token expiry", Area: "cloud", Group: "Cloudflare",
		Secret: c.TokenSecret, Run: cfTokensCheck(c), Probes: []Probe{tp}})
}

type cfRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority *int   `json:"priority"`
}

func cloudflareCheck(c *Cloudflare) func(context.Context, *Env) Result {
	base := strings.TrimSuffix(c.API, "/")
	return func(ctx context.Context, env *Env) Result {
		token, ok := env.Secret(c.TokenSecret)
		if !ok {
			return Unknownf("secret %s not in vault", c.TokenSecret)
		}
		hdr := map[string]string{"Authorization": "Bearer " + token}
		zoneID := c.ZoneID
		if zoneID == "" {
			var z struct {
				Result []struct {
					ID string `json:"id"`
				} `json:"result"`
			}
			q := url.Values{"name": {c.Zone}}
			if c.AccountID != "" {
				q.Set("account.id", c.AccountID)
			}
			if err := getJSON(ctx, env, base+"/zones?"+q.Encode(), hdr, &z); err != nil {
				return Unknownf("zone lookup: %v", err)
			}
			if len(z.Result) == 0 {
				return Critf("zone %s not visible to the token", c.Zone)
			}
			zoneID = z.Result[0].ID
		}
		var all []DNSRecord
		for pg := 1; pg < 50; pg++ {
			var r struct {
				Result     []cfRecord `json:"result"`
				ResultInfo struct {
					TotalPages int `json:"total_pages"`
				} `json:"result_info"`
			}
			u := fmt.Sprintf("%s/zones/%s/dns_records?per_page=500&page=%d", base, url.PathEscape(zoneID), pg)
			if err := getJSON(ctx, env, u, hdr, &r); err != nil {
				return Unknownf("records: %v", err)
			}
			for _, x := range r.Result {
				all = append(all, DNSRecord{Type: x.Type, Name: x.Name, Content: x.Content, Priority: x.Priority})
			}
			if pg >= r.ResultInfo.TotalPages {
				break
			}
		}
		return CompareRecords(all, c.Expected, c.Watch)
	}
}

func normRecord(r DNSRecord) string {
	t := strings.ToUpper(r.Type)
	content := strings.TrimSpace(r.Content)
	switch t {
	case "TXT":
		content = strings.ReplaceAll(strings.Trim(content, `"`), `" "`, "")
	case "A", "AAAA":
		if a, err := netip.ParseAddr(content); err == nil {
			content = a.String()
		}
	default:
		content = fqdn(content)
	}
	s := t + " " + fqdn(r.Name) + " " + content
	if r.Priority != nil && t == "MX" {
		s += fmt.Sprintf(" prio=%d", *r.Priority)
	}
	return s
}

// CompareRecords checks every expected record exists, and that the watched
// name/type pairs (the expected ones plus extra) hold nothing else.
func CompareRecords(actual, expected, watch []DNSRecord) Result {
	key := func(r DNSRecord) string { return strings.ToUpper(r.Type) + " " + fqdn(r.Name) }
	watched := map[string]bool{}
	want := map[string]bool{}
	for _, r := range expected {
		watched[key(r)] = true
		want[normRecord(r)] = true
	}
	for _, r := range watch {
		watched[key(r)] = true
	}
	have := map[string]bool{}
	var extra []string
	for _, r := range actual {
		// compare MX priority only when the expected record names one
		n := normRecord(r)
		if strings.EqualFold(r.Type, "MX") && !want[n] {
			nr := r
			nr.Priority = nil
			if want[normRecord(nr)] {
				n = normRecord(nr)
			}
		}
		have[n] = true
		if watched[key(r)] && !want[n] {
			extra = append(extra, n)
		}
	}
	var missing []string
	for n := range want {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	switch {
	case len(missing) > 0:
		msg := "missing: " + strings.Join(missing, "; ")
		if len(extra) > 0 {
			msg += "; unexpected: " + strings.Join(extra, "; ")
		}
		return Critf("%s", msg)
	case len(extra) > 0:
		return Warnf("unexpected: %s", strings.Join(extra, "; "))
	}
	return Okf("%d expected records present, %d records in zone", len(expected), len(actual))
}

// CFToken is an API token as Cloudflare's verify and list endpoints describe it.
type CFToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on"`
}

func cfTokensCheck(c *Cloudflare) func(context.Context, *Env) Result {
	base := strings.TrimSuffix(c.API, "/")
	return func(ctx context.Context, env *Env) Result {
		token, ok := env.Secret(c.TokenSecret)
		if !ok {
			return Unknownf("secret %s not in vault", c.TokenSecret)
		}
		hdr := map[string]string{"Authorization": "Bearer " + token}
		var v struct {
			Result CFToken `json:"result"`
		}
		err := getJSON(ctx, env, base+"/user/tokens/verify", hdr, &v)
		if err != nil && c.AccountID != "" {
			err = getJSON(ctx, env, base+"/accounts/"+url.PathEscape(c.AccountID)+"/tokens/verify", hdr, &v)
		}
		if err != nil {
			return Critf("verifying the token: %v", err)
		}
		lists := []string{base + "/user/tokens?per_page=50"}
		if c.AccountID != "" {
			lists = append(lists, base+"/accounts/"+url.PathEscape(c.AccountID)+"/tokens?per_page=50")
		}
		var listed []CFToken
		refused := false
		for _, u := range lists {
			var l struct {
				Result []CFToken `json:"result"`
			}
			if err := getJSON(ctx, env, u, hdr, &l); err != nil {
				if se, ok := err.(*httpStatusError); ok && (se.code == 403 || se.code == 401) {
					refused = true
					continue
				}
				return Unknownf("listing tokens: %v", err)
			}
			listed = append(listed, l.Result...)
		}
		return EvalCFTokens(v.Result, listed, refused, c.Tokens, c.TokenDays, env.now())
	}
}

// EvalCFTokens rates the named tokens (or, with none named, every active one) and this
// check's own token by status and days until they expire.
func EvalCFTokens(self CFToken, listed []CFToken, refused bool, names []string, days status.Threshold, now time.Time) Result {
	var watch []CFToken
	seen := map[string]bool{}
	s := OK
	var problems []string
	if len(names) > 0 {
		for _, n := range names {
			i := slices.IndexFunc(listed, func(t CFToken) bool { return t.Name == n })
			switch {
			case i >= 0:
				watch = append(watch, listed[i])
				seen[listed[i].ID] = true
			case refused:
				s = Worst(s, Warn)
				problems = append(problems, n+" not visible: listing tokens needs the API Tokens Read permission")
			default:
				s = Crit
				problems = append(problems, n+" not found")
			}
		}
	} else {
		for _, t := range listed {
			if t.Status == "active" && !seen[t.ID] {
				watch = append(watch, t)
				seen[t.ID] = true
			}
		}
	}
	if !seen[self.ID] {
		if i := slices.IndexFunc(listed, func(t CFToken) bool { return t.ID == self.ID }); i >= 0 {
			self.Name = listed[i].Name
		}
		if self.Name == "" {
			self.Name = "sitescope's token"
		}
		watch = append(watch, self)
	}
	type row struct {
		left time.Duration
		text string
	}
	var rows []row
	for _, t := range watch {
		if t.Status != "active" {
			s = Crit
			problems = append(problems, t.Name+" is "+t.Status)
			continue
		}
		exp, err := time.Parse(time.RFC3339, t.ExpiresOn)
		if err != nil {
			rows = append(rows, row{1 << 62, t.Name + " never expires"})
			continue
		}
		left := exp.Sub(now)
		d := left.Hours() / 24
		s = Worst(s, days.Below(d))
		rows = append(rows, row{left, fmt.Sprintf("%s expires %s (%.0f days)", t.Name, exp.UTC().Format("2006-01-02"), d)})
	}
	slices.SortFunc(rows, func(a, b row) int { return cmp.Compare(a.left, b.left) })
	var parts []string
	for _, r := range rows {
		parts = append(parts, r.text)
	}
	return Rated(s, "%s", strings.Join(append(problems, parts...), "; "))
}
