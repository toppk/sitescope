package hub

import (
	"context"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/status"
)

// spreadWindow bounds where a slow check's phase may fall, so a fresh hub has results soon.
const spreadWindow = 15 * time.Minute

// never parks a check that only runs when something triggers it.
var never = time.Unix(1<<40, 0)

// grid places every run on tick-sized steps from the hub's start, so work lands
// together and the hub sleeps between steps.
type grid struct {
	boot time.Time
	tick time.Duration
}

// at rounds t up to the next grid point.
func (g grid) at(t time.Time) time.Time {
	if !t.After(g.boot) {
		return g.boot
	}
	n := (t.Sub(g.boot) + g.tick - 1) / g.tick
	return g.boot.Add(n * g.tick)
}

// after returns the first run of the series anchor, anchor+interval, … at or after t.
func (g grid) after(anchor time.Time, interval time.Duration, t time.Time) time.Time {
	if !t.After(anchor) {
		return anchor
	}
	n := (t.Sub(anchor) + interval - 1) / interval
	return g.at(anchor.Add(n * interval))
}

// phases gives each check its offset from the start: checks sharing a rate-limited API
// are spread evenly over their interval, other slow checks get a stable spot in the
// first spreadWindow, and every-tick checks start at once.
func phases(checks []*check.Check, tick time.Duration) map[string]time.Duration {
	groups := map[string][]*check.Check{}
	for _, c := range checks {
		if c.Spread != "" {
			groups[c.Spread] = append(groups[c.Spread], c)
		}
	}
	out := map[string]time.Duration{}
	for _, c := range checks {
		switch {
		case c.Spread != "":
			g := groups[c.Spread]
			for i, m := range g {
				if m == c {
					out[c.ID] = c.Interval * time.Duration(i) / time.Duration(len(g))
				}
			}
		case c.Interval > tick:
			w := min(c.Interval, spreadWindow)
			f := fnv.New32a()
			f.Write([]byte(c.ID))
			out[c.ID] = (time.Duration(f.Sum32()) % w).Truncate(tick)
		}
	}
	return out
}

// plan returns each check's anchor (first slot); a check that ran before a restart keeps its pace.
func plan(checks []*check.Check, states map[string]*alert.State, g grid) map[string]time.Time {
	ph := phases(checks, g.tick)
	anchor := map[string]time.Time{}
	for _, c := range checks {
		a := g.at(g.boot.Add(ph[c.ID]))
		if st := states[c.ID]; st != nil && st.Status != status.Unknown && st.Status != status.Locked && !st.LastRun.IsZero() {
			if resume := g.at(st.LastRun.Add(c.Interval)); resume.After(a) {
				a = resume
			}
		}
		anchor[c.ID] = a
	}
	return anchor
}

func (h *Hub) schedule(ctx context.Context) {
	g := grid{boot: time.Now(), tick: h.cfg.Hub.Tick.D()}
	h.mu.Lock()
	anchor := plan(h.checks, h.states, g)
	next := map[string]time.Time{}
	dependents := map[string][]string{}
	for _, c := range h.checks {
		next[c.ID] = anchor[c.ID]
		if c.DependsOn != "" {
			dependents[c.DependsOn] = append(dependents[c.DependsOn], c.ID)
			next[c.ID] = never // runs when its agent's report arrives
		} else if st := h.states[c.ID]; st.LastRun.IsZero() {
			st.Message = "first run at " + anchor[c.ID].UTC().Format("01-02 15:04 UTC")
		}
	}
	h.mu.Unlock()

	sem := make(chan struct{}, h.cfg.Hub.Concurrency)
	results := make(chan result, len(h.checks))
	running := map[string]bool{}
	timer := time.NewTimer(0)
	defer timer.Stop()
	now := g.boot
	lastBeat, lastSave, lastPrune := now, now, now

	dispatch := func() {
		for _, c := range h.checks {
			if !running[c.ID] && !now.Before(next[c.ID]) {
				running[c.ID] = true
				go h.run(ctx, c, sem, results)
			}
		}
	}
	housekeeping := func() {
		h.notify(now)
		h.digest(now)
		if now.Sub(lastBeat) >= h.cfg.Hub.HeartbeatInterval.D() {
			lastBeat = now
			h.heartbeat(ctx)
		}
		if now.Sub(lastSave) >= 5*time.Minute {
			lastSave = now
			if err := h.store.SaveStates(h.snapshotStates()); err != nil {
				h.storeErr.Store(true)
				slog.Error("saving states failed", "err", err)
			}
		}
		if now.Sub(lastPrune) >= 6*time.Hour {
			lastPrune = now
			h.prune(now)
		}
	}
	// sleep until the next due check, but wake at least every few minutes for housekeeping
	rearm := func() {
		wake := g.at(now.Add(5 * time.Minute))
		for _, c := range h.checks {
			if !running[c.ID] && next[c.ID].Before(wake) {
				wake = next[c.ID]
			}
		}
		h.nextWake.Store(wake.Unix())
		timer.Reset(max(time.Until(wake), 0))
	}

	for {
		select {
		case <-ctx.Done():
			h.store.SaveStates(h.snapshotStates())
			return
		case id := <-h.wake:
			now = time.Now()
			next[id] = now
			dispatch()
		case res := <-results:
			now = time.Now()
			delete(running, res.c.ID)
			retry := h.handle(res)
			c := res.c
			switch {
			case retry:
				next[c.ID] = g.at(res.end.Add(c.RetryInterval))
			case res.r.RetryIn > 0:
				next[c.ID] = g.at(res.end.Add(min(res.r.RetryIn, c.Interval)))
			case c.DependsOn != "":
				next[c.ID] = never
			default:
				next[c.ID] = g.after(anchor[c.ID], c.Interval, res.end)
			}
			for _, d := range dependents[c.ID] {
				next[d] = now
			}
			dispatch()
			if len(running) == 0 {
				housekeeping() // the batch is done: one email for whatever it changed
			}
		case <-timer.C:
			now = time.Now()
			dispatch()
			housekeeping()
		}
		h.lastTick.Store(now.Unix())
		rearm()
	}
}
