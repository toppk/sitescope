package check

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/toppk/sitescope/internal/config"
)

type cfRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority *int   `json:"priority"`
}

func cloudflareCheck(c *config.Cloudflare) func(context.Context, *Env) Result {
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
			if err := getJSON(ctx, env, base+"/zones?name="+url.QueryEscape(c.Zone), hdr, &z); err != nil {
				return Unknownf("zone lookup: %v", err)
			}
			if len(z.Result) == 0 {
				return Critf("zone %s not visible to the token", c.Zone)
			}
			zoneID = z.Result[0].ID
		}
		var all []config.DNSRecord
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
				all = append(all, config.DNSRecord{Type: x.Type, Name: x.Name, Content: x.Content, Priority: x.Priority})
			}
			if pg >= r.ResultInfo.TotalPages {
				break
			}
		}
		return CompareRecords(all, c.Expected, c.Watch)
	}
}

func normRecord(r config.DNSRecord) string {
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
func CompareRecords(actual, expected, watch []config.DNSRecord) Result {
	key := func(r config.DNSRecord) string { return strings.ToUpper(r.Type) + " " + fqdn(r.Name) }
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
