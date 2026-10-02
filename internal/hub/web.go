package hub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
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
	mux.HandleFunc("GET /status.json", h.statusJSON)
	mux.Handle("GET /static/", staticFiles())
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
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; img-src 'self'; "+
			"style-src 'self'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func staticFiles() http.Handler {
	files := http.FileServerFS(static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	})
}

func (h *Hub) healthz(w http.ResponseWriter, _ *http.Request) {
	// the scheduler may sleep for minutes; it is stalled only when it misses its own wake-up
	if time.Since(time.Unix(h.nextWake.Load(), 0)) > 2*time.Minute {
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
	Days                     []status.Status
	Vis, Service, PublicName string
}

func (h *Hub) rows() []row {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]row, 0, len(h.checks))
	for _, c := range h.checks {
		r := row{Check: c, State: *h.states[c.ID]}
		r.Vis, r.Service, r.PublicName = h.visibility(c)
		out = append(out, r)
	}
	return out
}

// light is one service on the public page; a grouped (class B) service shows no breakdown.
type light struct {
	ID, Name  string
	Status    status.Status
	OK, Total int
	Grouped   bool
	Groups    []grp[item]
}

type item struct {
	Label, Group string
	Status       status.Status
}

// rules is the public config, then one public rule per area for checks it doesn't match.
func (h *Hub) rules() []config.Public {
	out := slices.Clip(h.cfg.Public)
	for _, a := range check.Areas {
		out = append(out, config.Public{Name: a.Name, Areas: []string{a.ID}, Visibility: config.VisPublic})
	}
	return out
}

// placement is the first rule a check matches.
func (h *Hub) placement(c *check.Check) config.Public {
	for _, p := range h.rules() {
		if p.Matches(c.ID, c.Area) {
			return p
		}
	}
	return config.Public{Visibility: config.VisPrivate}
}

// visibility describes where a check appears publicly, for the detail view and API.
func (h *Hub) visibility(c *check.Check) (vis, service, label string) {
	p := h.placement(c)
	if p.Visibility == config.VisPrivate {
		return config.VisPrivate, "", ""
	}
	if p.Visibility == config.VisPublic {
		label = publicLabel(p, c)
	}
	return p.Visibility, p.Name, label
}

func publicLabel(p config.Public, c *check.Check) string {
	if l := p.Labels[c.ID]; l != "" {
		return l
	}
	return c.Name
}

// lights computes the public page, one light per service name in rule order.
func (h *Hub) lights(rows []row) []light {
	type acc struct {
		name    string
		sts     []status.Status
		items   []item
		grouped bool
	}
	var accs []*acc
	idx := map[string]int{}
	for _, p := range h.rules() {
		if _, ok := idx[p.Name]; !ok && p.Visibility != config.VisPrivate {
			idx[p.Name] = len(accs)
			accs = append(accs, &acc{name: p.Name})
		}
	}
	for _, r := range rows {
		p := h.placement(r.Check)
		if p.Visibility == config.VisPrivate || r.Status == status.Locked {
			continue
		}
		a := accs[idx[p.Name]]
		a.sts = append(a.sts, r.Status)
		if p.Visibility == config.VisPublic {
			a.items = append(a.items, item{publicLabel(p, r.Check), r.Group, r.Status})
		} else {
			a.grouped = true
		}
	}
	var out []light
	for i, a := range accs {
		if len(a.sts) == 0 {
			continue
		}
		l := light{ID: fmt.Sprintf("s%d", i), Name: a.name, Status: status.Worst(a.sts...), Total: len(a.sts),
			Grouped: len(a.items) == 0}
		for _, s := range a.sts {
			if s == status.OK {
				l.OK++
			}
		}
		l.Groups = nest(l.ID, a.items, func(it item) string { return it.Group }, func(it item) status.Status { return it.Status })
		out = append(out, l)
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

// overallAll is the worst status of every check, private ones included.
func overallAll(rows []row) status.Status {
	var sts []status.Status
	for _, r := range rows {
		if r.Status != status.Locked {
			sts = append(sts, r.Status)
		}
	}
	return status.Worst(sts...)
}

func (h *Hub) public(w http.ResponseWriter, _ *http.Request) {
	ls := h.lights(h.rows())
	var sts []status.Status
	for _, l := range ls {
		for _, g := range l.Groups {
			for _, it := range g.Items {
				sts = append(sts, it.Status)
			}
		}
	}
	sub := ""
	if len(sts) > 0 {
		sub = summary(sts)
	}
	h.render(w, "public", map[string]any{"Page": "status",
		"Lights": ls, "Overall": overall(ls), "Summary": sub, "Locked": !h.vault.Unlocked(),
	})
}

// statusJSON is the public page as JSON: the same facts, nothing more.
func (h *Hub) statusJSON(w http.ResponseWriter, _ *http.Request) {
	ls := h.lights(h.rows())
	out := struct {
		Version  string        `json:"version"`
		Time     time.Time     `json:"time"`
		Overall  status.Status `json:"overall"`
		Locked   bool          `json:"vaultLocked"`
		Services []apiService  `json:"services"`
	}{Version: Version, Time: time.Now().UTC(), Overall: overall(ls), Locked: !h.vault.Unlocked(), Services: services(ls)}
	writeJSON(w, out)
}

func services(ls []light) []apiService {
	out := []apiService{}
	for _, l := range ls {
		s := apiService{Name: l.Name, Status: l.Status}
		for _, g := range l.Groups {
			for _, it := range g.Items {
				s.Checks = append(s.Checks, apiItem{it.Label, it.Group, it.Status})
			}
		}
		out = append(out, s)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (h *Hub) detail(w http.ResponseWriter, _ *http.Request) {
	rows := h.rows()
	now := time.Now()
	for i := range rows {
		hist, _ := h.store.History(rows[i].ID, now.AddDate(0, 0, -historyDays), 0)
		rows[i].Days = store.DailyWorst(hist, historyDays, now)
	}
	type area struct {
		ID, Name  string
		Status    status.Status
		OK, Total int
		Groups    []grp[row]
	}
	var areas []area
	var all []status.Status
	for i, a := range check.Areas {
		var rs []row
		for _, r := range rows {
			if r.Area == a.ID {
				rs = append(rs, r)
				all = append(all, r.Status)
			}
		}
		if len(rs) == 0 {
			continue
		}
		id := fmt.Sprintf("a%d", i)
		gs := nest(id, rs, func(r row) string { return r.Group }, func(r row) status.Status { return r.Status })
		ar := area{ID: id, Name: a.Name, Status: status.OK, Groups: gs}
		var sts []status.Status
		for _, g := range gs {
			ar.OK += g.OK
			ar.Total += g.Total
			if g.Status != status.Locked {
				sts = append(sts, g.Status)
			}
		}
		if len(sts) > 0 {
			ar.Status = status.Worst(sts...)
		} else {
			ar.Status = status.Locked
		}
		areas = append(areas, ar)
	}
	h.render(w, "detail", map[string]any{"Page": "detail", "Areas": areas, "Overall": overallAll(rows),
		"Summary": summary(all), "Locked": !h.vault.Unlocked()})
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
	rw := row{Check: c, State: st, Days: days}
	rw.Vis, rw.Service, rw.PublicName = h.visibility(c)
	h.render(w, "check", map[string]any{"Page": "detail", "Row": rw, "History": hist,
		"Locked": !h.vault.Unlocked()})
}

type apiCheck struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Area       string        `json:"area"`
	Status     status.Status `json:"status"`
	Since      time.Time     `json:"since"`
	LastRun    time.Time     `json:"lastRun"`
	TookMS     int64         `json:"tookMs"`
	Message    string        `json:"message"`
	Retrying   int           `json:"retrying,omitempty"`
	Visibility string        `json:"visibility"`
	Service    string        `json:"service,omitempty"`
	PublicName string        `json:"publicName,omitempty"`
}

func (h *Hub) apiStatus(w http.ResponseWriter, _ *http.Request) {
	rows := h.rows()
	out := struct {
		Version  string        `json:"version"`
		Time     time.Time     `json:"time"`
		Overall  status.Status `json:"overall"`
		Public   status.Status `json:"publicOverall"`
		Locked   bool          `json:"vaultLocked"`
		Services []apiService  `json:"services"`
		Checks   []apiCheck    `json:"checks"`
	}{Version: Version, Time: time.Now().UTC(), Locked: !h.vault.Unlocked(), Overall: overallAll(rows)}
	ls := h.lights(rows)
	out.Public = overall(ls)
	out.Services = services(ls)
	for _, r := range rows {
		out.Checks = append(out.Checks, apiCheck{r.ID, r.Name, r.Area, r.Status, r.Since, r.LastRun, r.TookMS,
			r.Message, r.Retrying, r.Vis, r.Service, r.PublicName})
	}
	writeJSON(w, out)
}

type apiService struct {
	Name   string        `json:"name"`
	Status status.Status `json:"status"`
	Checks []apiItem     `json:"checks,omitempty"`
}

type apiItem struct {
	Name   string        `json:"name"`
	Group  string        `json:"group,omitempty"`
	Status status.Status `json:"status"`
}

func (h *Hub) render(w http.ResponseWriter, name string, data map[string]any) {
	data["Title"] = h.cfg.Hub.Title
	data["Docs"] = h.cfg.Hub.DocsURL
	data["Version"] = Version
	data["Refresh"] = h.cfg.Hub.Refresh
	data["Now"] = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render", "page", name, "err", err)
	}
}
