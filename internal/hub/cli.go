package hub

import (
	"context"
	"fmt"
	"io"
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
