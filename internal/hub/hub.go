// Package hub schedules checks, keeps state and history, sends alerts and serves the status page.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
	"github.com/toppk/sitescope/internal/store"
)

type Hub struct {
	cfg    *config.Config
	checks []*check.Check
	byID   map[string]*check.Check
	env    *check.Env
	store  *store.Store
	vault  *Vault
	mailer *Mailer

	heartbeatURL string

	mu         sync.Mutex
	states     map[string]*alert.State
	recordedAt map[string]time.Time
	recorded   map[string]status.Status

	wake     chan string
	lastTick atomic.Int64
	nextWake atomic.Int64 // when the scheduler plans to wake, for /healthz
	started  time.Time
	storeErr atomic.Bool
}

// Version is shown in the page footer and /status.json; main sets it from the build.
var Version = "dev"

func New(cfg *config.Config) (*Hub, error) {
	checks, err := check.Build(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Hub.StateDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.Hub.StateDir, "history.db"))
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	h := &Hub{
		cfg: cfg, checks: checks, byID: map[string]*check.Check{}, store: st,
		vault:        &Vault{path: cfg.Hub.Vault, since: time.Now()},
		heartbeatURL: os.Getenv("SITESCOPE_HEARTBEAT_URL"),
		recordedAt:   map[string]time.Time{}, recorded: map[string]status.Status{},
		wake: make(chan string, 64),
	}
	h.mailer = &Mailer{cfg: cfg.Alerts, host: cfg.Hub.Hostname, url: cfg.Hub.PublicURL}
	h.env = &check.Env{
		HTTP:       &http.Client{Timeout: time.Minute},
		Hostname:   cfg.Hub.Hostname,
		AgentToken: os.Getenv("SITESCOPE_AGENT_TOKEN"),
		Secret:     h.vault.Get,
		Reports:    &check.Reports{},
	}
	if cfg.Hub.LockedAfter > 0 {
		h.checks = append(h.checks, h.vaultCheck())
	}
	h.states, err = st.States()
	if err != nil {
		return nil, err
	}
	for _, c := range h.checks {
		h.byID[c.ID] = c
		if h.states[c.ID] == nil {
			h.states[c.ID] = &alert.State{}
		}
		if e, ok := st.Last(c.ID); ok {
			h.recordedAt[c.ID], h.recorded[c.ID] = e.Time, e.Status
		}
	}
	return h, nil
}

func (h *Hub) Checks() []*check.Check { return h.checks }

// Run blocks until ctx ends; the vault is wiped on return.
func (h *Hub) Run(ctx context.Context) error {
	defer h.store.Close()
	defer h.vault.Lock()
	slog.Info("hub starting", "checks", len(h.checks), "listen", h.cfg.Hub.Listen)
	if h.env.AgentToken == "" && config.Get[*check.Hosts](h.cfg) != nil {
		slog.Warn("SITESCOPE_AGENT_TOKEN is not set; agent polls will fail")
	}
	h.vault.onChange = func() { h.wakeSecretChecks() }
	h.skipMissedDigest(time.Now())

	errc := make(chan error, 2)
	go func() { errc <- h.serveWeb(ctx) }()
	go func() { errc <- h.serveControl(ctx) }()

	h.mailer.Send(fmt.Sprintf("sitescope started on %s - vault LOCKED, run sitescope unlock", h.cfg.Hub.Hostname),
		fmt.Sprintf("sitescope started on %s at %s.\n\nThe vault is locked: checks that need credentials report \"locked\" until an operator runs\n\n  sitescope unlock\n\non %s.\n",
			h.cfg.Hub.Hostname, time.Now().Format(time.RFC1123), h.cfg.Hub.Hostname))

	go h.schedule(ctx)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

type result struct {
	c   *check.Check
	r   check.Result
	end time.Time
}

func (h *Hub) run(ctx context.Context, c *check.Check, sem chan struct{}, out chan<- result) {
	if c.Secret != "" && !h.vault.Unlocked() {
		out <- result{c, check.Result{Status: status.Locked, Message: "vault locked"}, time.Now()}
		return
	}
	sem <- struct{}{}
	defer func() { <-sem }()
	r := RunOnce(ctx, c, h.env)
	out <- result{c, r, time.Now()}
}

// RunOnce runs a check with its timeout and turns panics into crit results.
func RunOnce(ctx context.Context, c *check.Check, env *check.Env) (r check.Result) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			slog.Error("check panicked", "check", c.ID, "panic", p, "stack", string(debug.Stack()))
			r = check.Critf("internal error")
		}
		r.Took = time.Since(start)
		if r.Status == status.Unknown && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			r.Message = "timed out: " + r.Message
		}
	}()
	return c.Run(ctx, env)
}

// handle applies a result to state and history, returning whether to retry soon.
func (h *Hub) handle(res result) bool {
	h.mu.Lock()
	st := h.states[res.c.ID]
	changed, retry := st.Observe(res.r.Status, res.r.Message, res.r.Took, res.c.Retries, res.end)
	cp := *st
	var e store.Entry
	if changed || h.recorded[res.c.ID] != res.r.Status || res.end.Sub(h.recordedAt[res.c.ID]) >= h.cfg.Hub.SampleEvery.D() {
		e = store.Entry{Time: res.end, Status: res.r.Status, TookMS: uint32(res.r.Took.Milliseconds()), Message: res.r.Message}
		h.recorded[res.c.ID], h.recordedAt[res.c.ID] = res.r.Status, res.end
	}
	h.mu.Unlock()
	if changed {
		slog.Info("state change", "check", res.c.ID, "status", cp.Status.String(), "message", res.r.Message)
	}
	if e.Time.IsZero() && !changed && !retry {
		return false
	}
	if err := h.store.Record(res.c.ID, e, &cp); err != nil {
		h.storeErr.Store(true)
		slog.Error("store write failed", "err", err)
	}
	return retry
}

func (h *Hub) snapshotStates() map[string]*alert.State {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]*alert.State, len(h.states))
	for id, s := range h.states {
		cp := *s
		out[id] = &cp
	}
	return out
}

func (h *Hub) wakeSecretChecks() {
	for _, c := range h.checks {
		if c.Secret != "" || c.ID == vaultCheckID {
			select {
			case h.wake <- c.ID:
			default:
			}
		}
	}
}

func (h *Hub) heartbeat(ctx context.Context) {
	if h.storeErr.Swap(false) {
		slog.Warn("skipping heartbeat: store errors in the last cycle")
		return
	}
	if h.heartbeatURL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", h.heartbeatURL, nil)
		if err != nil {
			slog.Error("heartbeat", "err", err)
			return
		}
		resp, err := h.env.HTTP.Do(req)
		if err != nil {
			slog.Warn("heartbeat failed", "err", err)
			return
		}
		resp.Body.Close()
	}()
}

func (h *Hub) prune(now time.Time) {
	keep := map[string]bool{}
	for _, c := range h.checks {
		keep[c.ID] = true
	}
	if err := h.store.Prune(now.AddDate(0, 0, -h.cfg.Hub.RetentionDays), keep); err != nil {
		slog.Error("prune failed", "err", err)
	}
}
