package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

// Ntfy pushes state changes to an ntfy topic; the topic URL and token come from the environment.
type Ntfy struct {
	cfg   config.Ntfy
	url   string // SITESCOPE_NTFY_URL: server and topic
	token string // SITESCOPE_NTFY_TOKEN, optional
	host  string
	link  string
	http  *http.Client
	retry time.Duration
}

func (n *Ntfy) Name() string { return "ntfy" }

func (n *Ntfy) Enabled() bool { return n.cfg.Enabled && n.url != "" }

// Send pushes only changes at or above cfg.Min, and their recoveries; the rest is left to email.
func (n *Ntfy) Send(m Message) error {
	if m.Kind != KindChange {
		return nil
	}
	min := status.Crit
	if n.cfg.Min == "warn" {
		min = status.Warn
	}
	counts := map[string]int{}
	var names []string
	for _, c := range m.Changes {
		switch {
		case c.To.Rank() >= min.Rank():
			counts[c.To.String()]++
			names = append(names, c.Name)
		case c.From.Rank() >= min.Rank():
			counts["recovered"]++
			names = append(names, c.Name+" recovered")
		}
	}
	if len(names) == 0 {
		return nil
	}
	var parts []string
	for _, k := range []string{"crit", "warn", "recovered"} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
	}
	body := strings.Join(parts, ", ")
	if n.cfg.Details {
		body += "\n" + strings.Join(names, "\n")
	}
	prio, tag := "default", "white_check_mark"
	switch {
	case counts["crit"] > 0:
		prio, tag = "high", "rotating_light"
	case counts["warn"] > 0:
		tag = "warning"
	}
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(n.retry)
		}
		var retry bool
		if retry, err = n.post("sitescope "+n.host, body, prio, tag); err == nil || !retry {
			return err
		}
	}
	return err
}

// post reports whether a failure is worth retrying.
func (n *Ntfy) post(title, body, prio, tag string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", n.url, strings.NewReader(body))
	if err != nil {
		return false, errors.New("bad SITESCOPE_NTFY_URL") // the URL holds the topic; keep it out of logs
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", prio)
	req.Header.Set("Tags", tag)
	if n.link != "" {
		req.Header.Set("Click", strings.TrimSuffix(n.link, "/")+"/detail")
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			err = ue.Err // drop the URL, which holds the topic
		}
		return true, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return false, nil
	}
	return resp.StatusCode == 429 || resp.StatusCode >= 500, fmt.Errorf("ntfy returned %s", resp.Status)
}
