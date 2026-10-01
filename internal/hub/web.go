package hub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/status"
	"github.com/toppk/sitescope/internal/store"
)

const (
	AdminSecret = "admin_password_hash"
	historyDays = 30
)

func (h *Hub) serveWeb(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.public)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.Handle("GET /detail", h.auth(http.HandlerFunc(h.detail)))
	mux.Handle("GET /detail/check", h.auth(http.HandlerFunc(h.checkPage)))
	mux.Handle("GET /api/status", h.auth(http.HandlerFunc(h.apiStatus)))
	srv := &http.Server{Addr: h.cfg.Hub.Listen, Handler: headers(mux),
		ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (h *Hub) healthz(w http.ResponseWriter, _ *http.Request) {
	if time.Since(time.Unix(h.lastTick.Load(), 0)) > 2*time.Minute {
		http.Error(w, "scheduler stalled", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

type authCache struct {
	mu       sync.Mutex
	ok       map[[32]byte]time.Time
	lastFail time.Time
}

var admins authCache

// auth checks HTTP basic auth (user "admin") against the bcrypt hash in the vault.
func (h *Hub) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !h.vault.Unlocked() {
			http.Error(w, "vault locked: the detailed view is unavailable until an operator runs sitescope unlock", http.StatusServiceUnavailable)
			return
		}
		user, pass, ok := r.BasicAuth()
		if ok && h.checkPassword(user, pass) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="sitescope", charset="UTF-8"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (h *Hub) checkPassword(user, pass string) bool {
	if subtle.ConstantTimeCompare([]byte(user), []byte("admin")) != 1 {
		return false
	}
	// a hit in the cache spares bcrypt on every page load; the cache dies with the lock
	k := sha256.Sum256([]byte(pass))
	admins.mu.Lock()
	defer admins.mu.Unlock()
	if exp, ok := admins.ok[k]; ok && time.Now().Before(exp) && h.vault.Unlocked() {
		return true
	}
	if time.Since(admins.lastFail) < time.Second {
		return false
	}
	match := false
	h.vault.With(AdminSecret, func(hash []byte) {
		match = bcrypt.CompareHashAndPassword(hash, []byte(pass)) == nil
	})
	if !match {
		admins.lastFail = time.Now()
		slog.Warn("admin login failed")
		return false
	}
	if admins.ok == nil {
		admins.ok = map[[32]byte]time.Time{}
	}
	admins.ok[k] = time.Now().Add(10 * time.Minute)
	return true
}

func clearAuthCache() {
	admins.mu.Lock()
	admins.ok = nil
	admins.mu.Unlock()
}

type row struct {
	*check.Check
	alert.State
	Days []status.Status
}

func (h *Hub) rows() []row {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]row, 0, len(h.checks))
	for _, c := range h.checks {
		out = append(out, row{Check: c, State: *h.states[c.ID]})
	}
	return out
}

type light struct {
	Name   string
	Status status.Status
}

// lights computes the public per-service status from whole areas.
func (h *Hub) lights(rows []row) []light {
	type svc struct {
		name  string
		areas []string
	}
	var svcs []svc
	for _, p := range h.cfg.Public {
		svcs = append(svcs, svc{p.Name, p.Areas})
	}
	if len(svcs) == 0 {
		for _, a := range check.Areas {
			svcs = append(svcs, svc{a.Name, []string{a.ID}})
		}
	}
	var out []light
	for _, s := range svcs {
		var sts []status.Status
		for _, r := range rows {
			if slices.Contains(s.areas, r.Area) && r.Status != status.Locked {
				sts = append(sts, r.Status)
			}
		}
		if len(sts) > 0 {
			out = append(out, light{s.name, status.Worst(sts...)})
		}
	}
	return out
}

func overall(ls []light) status.Status {
	var sts []status.Status
	for _, l := range ls {
		sts = append(sts, l.Status)
	}
	return status.Worst(sts...)
}

func (h *Hub) public(w http.ResponseWriter, _ *http.Request) {
	ls := h.lights(h.rows())
	h.render(w, "public", map[string]any{
		"Lights": ls, "Overall": overall(ls), "Locked": !h.vault.Unlocked(),
	})
}

func (h *Hub) detail(w http.ResponseWriter, _ *http.Request) {
	rows := h.rows()
	now := time.Now()
	for i := range rows {
		hist, _ := h.store.History(rows[i].ID, now.AddDate(0, 0, -historyDays), 0)
		rows[i].Days = store.DailyWorst(hist, historyDays, now)
	}
	type group struct {
		Name string
		Rows []row
	}
	var groups []group
	for _, a := range check.Areas {
		g := group{Name: a.Name}
		for _, r := range rows {
			if r.Area == a.ID {
				g.Rows = append(g.Rows, r)
			}
		}
		slices.SortStableFunc(g.Rows, func(a, b row) int { return b.Status.Rank() - a.Status.Rank() })
		if len(g.Rows) > 0 {
			groups = append(groups, g)
		}
	}
	ls := h.lights(rows)
	h.render(w, "detail", map[string]any{"Groups": groups, "Overall": overall(ls), "Locked": !h.vault.Unlocked()})
}

func (h *Hub) checkPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	c := h.byID[id]
	if c == nil {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	st := *h.states[id]
	h.mu.Unlock()
	now := time.Now()
	hist, _ := h.store.History(id, now.AddDate(0, 0, -historyDays), 0)
	days := store.DailyWorst(hist, historyDays, now)
	if len(hist) > 500 {
		hist = hist[:500]
	}
	h.render(w, "check", map[string]any{"Row": row{Check: c, State: st, Days: days}, "History": hist,
		"Locked": !h.vault.Unlocked()})
}

type apiCheck struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Area     string        `json:"area"`
	Status   status.Status `json:"status"`
	Since    time.Time     `json:"since"`
	LastRun  time.Time     `json:"lastRun"`
	TookMS   int64         `json:"tookMs"`
	Message  string        `json:"message"`
	Retrying int           `json:"retrying,omitempty"`
}

func (h *Hub) apiStatus(w http.ResponseWriter, _ *http.Request) {
	rows := h.rows()
	out := struct {
		Time     time.Time     `json:"time"`
		Overall  status.Status `json:"overall"`
		Locked   bool          `json:"vaultLocked"`
		Services []apiService  `json:"services"`
		Checks   []apiCheck    `json:"checks"`
	}{Time: time.Now().UTC(), Locked: !h.vault.Unlocked()}
	ls := h.lights(rows)
	out.Overall = overall(ls)
	for _, l := range ls {
		out.Services = append(out.Services, apiService{l.Name, l.Status})
	}
	for _, r := range rows {
		out.Checks = append(out.Checks, apiCheck{r.ID, r.Name, r.Area, r.Status, r.Since, r.LastRun, r.TookMS, r.Message, r.Retrying})
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

type apiService struct {
	Name   string        `json:"name"`
	Status status.Status `json:"status"`
}

func (h *Hub) render(w http.ResponseWriter, name string, data map[string]any) {
	data["Title"] = h.cfg.Hub.Title
	data["Refresh"] = h.cfg.Hub.Refresh
	data["Now"] = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render", "page", name, "err", err)
	}
}
