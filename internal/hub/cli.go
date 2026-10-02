package hub

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

// CheckOnce runs the matching checks one time and prints their results;
// agent polls run first so the host checks have reports to read.
func CheckOnce(ctx context.Context, cfg *config.Config, match string, out io.Writer) (status.Status, error) {
	checks, err := check.Build(cfg)
	if err != nil {
		return status.Unknown, err
	}
	env := &check.Env{HTTP: &http.Client{Timeout: time.Minute}, Hostname: cfg.Hub.Hostname,
		AgentToken: os.Getenv("SITESCOPE_AGENT_TOKEN"), Reports: &check.Reports{},
		Secret: func(string) (string, bool) { return "", false }}
	var first, second []*check.Check
	for _, c := range checks {
		if c.DependsOn != "" {
			second = append(second, c)
		} else {
			first = append(first, c)
		}
	}
	results := map[string]check.Result{}
	var mu sync.Mutex
	runAll := func(cs []*check.Check) {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, c := range cs {
			wanted := match == "" || strings.Contains(c.ID, match)
			if !wanted && !slices.ContainsFunc(second, func(d *check.Check) bool {
				return d.DependsOn == c.ID && strings.Contains(d.ID, match)
			}) {
				continue
			}
			wg.Go(func() {
				var r check.Result
				if c.Secret != "" {
					r = check.Result{Status: status.Locked, Message: "needs vault secret " + c.Secret + " (hub only)"}
				} else {
					sem <- struct{}{}
					r = RunOnce(ctx, c, env)
					<-sem
				}
				if wanted {
					mu.Lock()
					results[c.ID] = r
					mu.Unlock()
				}
			})
		}
		wg.Wait()
	}
	runAll(first)
	runAll(second)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	worst := status.OK
	for _, c := range checks {
		r, ok := results[c.ID]
		if !ok {
			continue
		}
		worst = status.Worst(worst, r.Status)
		fmt.Fprintf(tw, "%s\t%s\t%dms\t%s\n", r.Status, c.ID, r.Took.Milliseconds(), r.Message)
	}
	tw.Flush()
	return worst, nil
}

// Probes prints every network contact the hub makes, by destination, with steady-state rates.
func Probes(cfg *config.Config, out io.Writer) error {
	checks, err := check.Build(cfg)
	if err != nil {
		return err
	}
	type line struct {
		what     string
		interval time.Duration
		checks   int
		perRun   int
	}
	type dest struct {
		name, port string
		perHour    float64
		lines      []*line
	}
	dests := map[string]*dest{}
	maxRetries := 0
	for _, c := range checks {
		maxRetries = max(maxRetries, c.Retries)
		for _, p := range c.Probes {
			if h, _, err := net.SplitHostPort(p.Dest); err == nil {
				p.Dest = h
			}
			k := p.Dest + " " + p.Port
			d := dests[k]
			if d == nil {
				d = &dest{name: p.Dest, port: p.Port}
				dests[k] = d
			}
			d.perHour += float64(p.Count) * float64(time.Hour) / float64(c.Interval)
			i := slices.IndexFunc(d.lines, func(l *line) bool { return l.what == p.What && l.interval == c.Interval })
			if i < 0 {
				d.lines = append(d.lines, &line{what: p.What, interval: c.Interval})
				i = len(d.lines) - 1
			}
			d.lines[i].checks++
			d.lines[i].perRun += p.Count
		}
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range dests {
			if !yield(k) {
				return
			}
		}
	})
	var total float64
	for _, k := range keys {
		d := dests[k]
		total += d.perHour
		fmt.Fprintf(out, "%s %s  %s\n", d.name, d.port, rate(d.perHour))
		for _, l := range d.lines {
			n := "1 check"
			if l.checks > 1 {
				n = fmt.Sprintf("%d checks", l.checks)
			}
			fmt.Fprintf(out, "    %-9s %s (%s every %s)\n",
				rate(float64(l.perRun)*float64(time.Hour)/float64(l.interval)), l.what, n, every(l.interval))
		}
	}
	fmt.Fprintf(out, "\n%d destinations, %s in all when healthy. A failing check reruns up to %d more times\n"+
		"(retryInterval apart) before alerting, then keeps its normal interval; agent-derived checks make no contacts.\n",
		len(keys), rate(total), maxRetries)
	return nil
}

// rate formats contacts per hour, as per day when under one an hour.
func rate(perHour float64) string {
	if perHour < 1 {
		return fmt.Sprintf("%.0f/day", perHour*24)
	}
	return fmt.Sprintf("%.0f/h", perHour)
}

func every(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
