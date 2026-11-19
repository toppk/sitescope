package hub

import (
	"context"
	"fmt"
	"io"
	"maps"
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
func CheckOnce(ctx context.Context, cfg *config.Config, match string) ([]CheckResult, error) {
	checks, err := check.Build(cfg)
	if err != nil {
		return nil, err
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
	var rows []CheckResult
	for _, c := range checks {
		if r, ok := results[c.ID]; ok {
			rows = append(rows, CheckResult{r.Status, c.ID, c.Name, r.Took.Milliseconds(), r.Message})
		}
	}
	if len(rows) == 0 && match != "" {
		return nil, fmt.Errorf("check: no check id contains %q; 'sitescope check -config FILE' runs them all", match)
	}
	return rows, nil
}

type CheckResult struct {
	Status  status.Status `json:"status"`
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	TookMS  int64         `json:"tookMs"`
	Message string        `json:"message"`
}

func WriteChecks(out io.Writer, rows []CheckResult) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%dms\t%s\n", r.Status, r.ID, r.TookMS, r.Message)
	}
	tw.Flush()
}

// Probes prints every network contact the hub makes, by destination, with steady-state rates.
// ProbeReport is every destination the hub contacts when all is healthy.
type ProbeReport struct {
	Destinations []Destination `json:"destinations"`
	PerHour      float64       `json:"perHour"`
	// MaxRetries is how many more times a failing check reruns before alerting.
	MaxRetries int `json:"maxRetries"`
}

type Destination struct {
	Name    string       `json:"name"`
	Port    string       `json:"port"`
	PerHour float64      `json:"perHour"`
	Probes  []ProbeGroup `json:"probes"`
}

// ProbeGroup is one kind of contact from checks sharing an interval.
type ProbeGroup struct {
	What        string  `json:"what"`
	IntervalSec float64 `json:"intervalSec"`
	Checks      int     `json:"checks"`
	PerRun      int     `json:"perRun"`
	PerHour     float64 `json:"perHour"`
}

func Probes(cfg *config.Config) (*ProbeReport, error) {
	checks, err := check.Build(cfg)
	if err != nil {
		return nil, err
	}
	dests := map[string]*Destination{}
	rep := &ProbeReport{}
	for _, c := range checks {
		rep.MaxRetries = max(rep.MaxRetries, c.Retries)
		for _, p := range c.Probes {
			if h, _, err := net.SplitHostPort(p.Dest); err == nil {
				p.Dest = h
			}
			k := p.Dest + " " + p.Port
			d := dests[k]
			if d == nil {
				d = &Destination{Name: p.Dest, Port: p.Port}
				dests[k] = d
			}
			perHour := float64(p.Count) * float64(time.Hour) / float64(c.Interval)
			d.PerHour += perHour
			rep.PerHour += perHour
			i := slices.IndexFunc(d.Probes, func(g ProbeGroup) bool { return g.What == p.What && g.IntervalSec == c.Interval.Seconds() })
			if i < 0 {
				d.Probes = append(d.Probes, ProbeGroup{What: p.What, IntervalSec: c.Interval.Seconds()})
				i = len(d.Probes) - 1
			}
			d.Probes[i].Checks++
			d.Probes[i].PerRun += p.Count
			d.Probes[i].PerHour += perHour
		}
	}
	for _, k := range slices.Sorted(maps.Keys(dests)) {
		rep.Destinations = append(rep.Destinations, *dests[k])
	}
	return rep, nil
}

func WriteProbes(out io.Writer, rep *ProbeReport) {
	for _, d := range rep.Destinations {
		fmt.Fprintf(out, "%s %s  %s\n", d.Name, d.Port, rate(d.PerHour))
		for _, g := range d.Probes {
			n := "1 check"
			if g.Checks > 1 {
				n = fmt.Sprintf("%d checks", g.Checks)
			}
			fmt.Fprintf(out, "    %-9s %s (%s every %s)\n", rate(g.PerHour), g.What, n, every(time.Duration(g.IntervalSec*float64(time.Second))))
		}
	}
	fmt.Fprintf(out, "\n%d destinations, %s in all when healthy. A failing check reruns up to %d more times\n"+
		"(retryInterval apart) before alerting, then keeps its normal interval; agent-derived checks make no contacts.\n",
		len(rep.Destinations), rate(rep.PerHour), rep.MaxRetries)
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
