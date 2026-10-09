package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Expect is what Verify checks beyond a healthy /healthz; zero values and negative counts are skipped.
type Expect struct {
	Version  string // exact, or the release alone when it has no "+rev"
	Vault    string // "locked" or "unlocked"
	Overall  string
	Services int
	Checks   int
}

// Verify reads a hub's /healthz and /status.json, prints one line per expectation and fails if any is unmet.
func Verify(ctx context.Context, c *http.Client, base string, want Expect, out io.Writer) error {
	base = strings.TrimSuffix(base, "/")
	failed := 0
	report := func(ok bool, what, got, exp string) {
		if ok {
			fmt.Fprintf(out, "ok    %-9s %s\n", what, got)
			return
		}
		failed++
		fmt.Fprintf(out, "FAIL  %-9s %s, want %s\n", what, got, exp)
	}

	body, code, err := get(ctx, c, base+"/healthz")
	if err != nil {
		return err
	}
	report(code == 200 && strings.TrimSpace(string(body)) == "ok", "healthz", fmt.Sprintf("%d %s", code, strings.TrimSpace(string(body))), "200 ok")

	body, code, err = get(ctx, c, base+"/status.json")
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("/status.json returned %d", code)
	}
	var doc StatusDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("/status.json: %w", err)
	}
	if want.Version != "" {
		got := doc.Version
		if !strings.Contains(want.Version, "+") {
			got, _, _ = strings.Cut(got, "+")
		}
		report(got == want.Version, "version", doc.Version, want.Version)
	}
	vault := "unlocked"
	if doc.Locked {
		vault = "locked"
	}
	if want.Vault != "" {
		report(vault == want.Vault, "vault", vault, want.Vault)
	}
	if want.Overall != "" {
		report(doc.Overall.String() == want.Overall, "overall", doc.Overall.String(), want.Overall)
	}
	checks := 0
	for _, s := range doc.Services {
		checks += len(s.Checks)
	}
	if want.Services >= 0 {
		report(len(doc.Services) == want.Services, "services", fmt.Sprint(len(doc.Services)), fmt.Sprint(want.Services))
	}
	if want.Checks >= 0 {
		report(checks == want.Checks, "checks", fmt.Sprint(checks), fmt.Sprint(want.Checks))
	}
	if failed > 0 {
		return fmt.Errorf("%d expectations not met", failed)
	}
	return nil
}

func get(ctx context.Context, c *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "sitescope-verify")
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, err
}
