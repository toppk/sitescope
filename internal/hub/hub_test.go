package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
	"github.com/toppk/sitescope/internal/vault"
)

func testHub(t *testing.T) *Hub {
	t.Helper()
	b, err := os.ReadFile("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b = bytes.Replace(b, []byte(`"hub": {`), []byte(`"hub": {"stateDir": "`+dir+`",`), 1)
	cfg, err := config.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Alerts.Enabled = false
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.store.Close() })
	return h
}

func TestChangeMail(t *testing.T) {
	subj, body := ChangeMail([]change{{id: "a", name: "alpha disk", msg: "/ 95%", from: status.OK, to: status.Crit}})
	if subj != "CRIT: alpha disk" || !strings.Contains(body, "/ 95%") {
		t.Errorf("single: %q %q", subj, body)
	}
	subj, _ = ChangeMail([]change{{to: status.OK, from: status.Crit}})
	if !strings.HasPrefix(subj, "RECOVERED") {
		t.Errorf("recovery subject %q", subj)
	}
	subj, body = ChangeMail([]change{
		{name: "x", to: status.OK, from: status.Warn},
		{name: "y", to: status.Crit, from: status.OK},
		{name: "z", to: status.Crit},
	})
	if subj != "3 changes: 2 crit, 1 recovered" || strings.Index(body, "y") > strings.Index(body, "x (was") {
		t.Errorf("multi: %q\n%s", subj, body)
	}
	m := &Mailer{cfg: config.Alerts{From: "s@example.org", To: []string{"a@example.org"}, SubjectPrefix: "[ss]"}, url: "https://status.example.org"}
	msg := string(m.message("CRIT: x", "line1\nline2", time.Now()))
	for _, want := range []string{"Subject: [ss] CRIT: x\r\n", "Auto-Submitted: auto-generated", "line1\r\nline2", "/detail"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q", want)
		}
	}
}

func TestHandleRetriesAndRecords(t *testing.T) {
	h := testHub(t)
	c := h.byID["http.portal"]
	now := time.Now()
	fail := check.Critf("connection refused")
	for i := range c.Retries {
		if !h.handle(result{c, fail, now.Add(time.Duration(i) * time.Second)}) {
			t.Fatal("expected a retry")
		}
	}
	if h.handle(result{c, fail, now.Add(time.Minute)}) {
		t.Fatal("retries exhausted, should commit")
	}
	if h.states[c.ID].Status != status.Crit {
		t.Fatal("not committed")
	}
	hist, _ := h.store.History(c.ID, time.Time{}, 0)
	if len(hist) != 2 {
		t.Fatalf("history has %d entries, want first failure and commit only", len(hist))
	}
	states, _ := h.store.States()
	if states[c.ID].Status != status.Crit {
		t.Fatal("state not persisted")
	}
}

func TestPublicPageRevealsNothing(t *testing.T) {
	h := testHub(t)
	h.cfg.Public = []config.Public{
		{Name: "DNS", Areas: []string{"dns"}, Visibility: config.VisGrouped},
		{Name: "Web", Areas: []string{"http", "tls"}, Visibility: config.VisGrouped},
		{Checks: []string{"*"}, Visibility: config.VisPrivate},
	}
	for range 3 {
		h.handle(result{h.byID["dns.soa.example.org.alpha.v4"], check.Critf("serial 1 behind 192.0.2.1 alpha"), time.Now()})
	}
	h.handle(result{h.byID["http.portal"], check.Okf("status 200 in 5ms"), time.Now()})
	w := httptest.NewRecorder()
	h.public(w, httptest.NewRequest("GET", "/", nil))
	page := w.Body.String()
	w = httptest.NewRecorder()
	h.statusJSON(w, httptest.NewRequest("GET", "/status.json", nil))
	page += w.Body.String()
	for _, leak := range []string{"192.0.2", "alpha", "serial", "portal", "example.org", "Mail"} {
		if strings.Contains(page, leak) {
			t.Errorf("public page leaks %q", leak)
		}
	}
	if !strings.Contains(w.Body.String(), `"overall": "crit"`) {
		t.Error("status.json lacks the overall status")
	}
	if !strings.Contains(page, "Vault locked") || !strings.Contains(page, "Outage") {
		t.Error("public page should show the lock banner and the DNS outage")
	}
}

func TestVisibilityClasses(t *testing.T) {
	h := testHub(t)
	h.cfg.Public = []config.Public{
		{Name: "Website", Checks: []string{"http.*"}, Visibility: config.VisPublic, Labels: map[string]string{"http.portal": "Customer portal"}},
		{Checks: []string{"dns.soa.*"}, Visibility: config.VisPrivate},
		{Name: "DNS", Areas: []string{"dns"}, Visibility: config.VisGrouped},
	}
	for range 3 {
		h.handle(result{h.byID["dns.soa.example.org.alpha.v4"], check.Critf("no answer"), time.Now()})
	}
	h.handle(result{h.byID["dns.primary"], check.Okf("all zones"), time.Now()})
	h.handle(result{h.byID["http.portal"], check.Okf("status 200 in 5ms"), time.Now()})
	w := httptest.NewRecorder()
	h.public(w, httptest.NewRequest("GET", "/", nil))
	page := w.Body.String()
	if !strings.Contains(page, "Customer portal") || !strings.Contains(page, "Website") {
		t.Error("public check should be listed under its label")
	}
	if strings.Contains(page, "Outage") {
		t.Error("private checks must not count")
	}
	if _, svc, _ := h.visibility(h.byID["dns.primary"]); svc != "DNS" {
		t.Errorf("dns.primary grouped into %q", svc)
	}
	if vis, svc, label := h.visibility(h.byID["mail.banner.alpha.v4"]); vis != config.VisPublic || svc != "Mail" || label == "" {
		t.Errorf("checks matching no rule are public under their area, got %s %q %q", vis, svc, label)
	}
	w = httptest.NewRecorder()
	h.detail(w, httptest.NewRequest("GET", "/detail", nil))
	if d := w.Body.String(); !strings.Contains(d, "public as &ldquo;Customer portal&rdquo; under Website") ||
		!strings.Contains(d, "grouped into DNS") || !strings.Contains(d, "private") || !strings.Contains(d, "Major outage") {
		t.Error("detail view should show every check's visibility and the full overall status")
	}
	w = httptest.NewRecorder()
	h.checkPage(w, httptest.NewRequest("GET", "/detail/check?id=dns.primary", nil))
	if !strings.Contains(w.Body.String(), "grouped into DNS") {
		t.Error("check page lacks visibility")
	}
	if _, err := config.Parse([]byte(`{"public": [{"name": "x", "areas": ["dns"], "visibility": "secret"}]}`)); err == nil {
		t.Error("bad visibility accepted")
	}
}

func TestDetailNeedsUnlockedVaultAndPassword(t *testing.T) {
	h := testHub(t)
	srv := httptest.NewServer(h.auth(http.HandlerFunc(h.apiStatus)))
	defer srv.Close()
	get := func(user, pass string) int {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("admin", "pw"); code != http.StatusServiceUnavailable {
		t.Fatalf("locked vault: %d", code)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	e := vault.NewEdit()
	e.Set(AdminSecret, hash)
	if err := vault.Save(h.vault.path, []byte("vault-pass"), nil, e); err != nil {
		t.Fatal(err)
	}
	e.Destroy()
	if err := h.vault.Unlock([]byte("vault-pass")); err != nil {
		t.Fatal(err)
	}
	if code := get("", ""); code != http.StatusUnauthorized {
		t.Errorf("no credentials: %d", code)
	}
	if code := get("admin", "pw"); code != http.StatusOK {
		t.Errorf("right password: %d", code)
	}
	time.Sleep(1100 * time.Millisecond)
	if code := get("admin", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", code)
	}
	h.vault.Lock()
	if code := get("admin", "pw"); code != http.StatusServiceUnavailable {
		t.Errorf("after lock: %d", code)
	}
}

func TestControlSocket(t *testing.T) {
	h := testHub(t)
	h.cfg.Hub.ControlSocket = filepath.Join(t.TempDir(), "c.sock")
	e := vault.NewEdit()
	e.Set("linode_token", []byte("t"))
	vault.Save(h.vault.path, []byte("vault-pass"), nil, e)
	e.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.serveControl(ctx)
	time.Sleep(100 * time.Millisecond)

	send := func(cmd, pass string) string {
		c, err := dialUnix(h.cfg.Hub.ControlSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(cmd + "\n" + pass))
		c.CloseWrite()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		return strings.TrimSpace(string(buf[:n]))
	}
	if got := send("unlock", "nope"); got != "err wrong passphrase" {
		t.Errorf("wrong pass: %q", got)
	}
	if got := send("unlock", "vault-pass"); !strings.HasPrefix(got, "ok unlocked, 1") || !h.vault.Unlocked() {
		t.Errorf("unlock: %q", got)
	}
	if got := send("status", ""); !strings.Contains(got, "linode_token") {
		t.Errorf("status: %q", got)
	}
	if got := send("lock", ""); got != "ok locked" || h.vault.Unlocked() {
		t.Errorf("lock: %q", got)
	}
	if fi, _ := os.Stat(h.cfg.Hub.ControlSocket); fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
}

func dialUnix(path string) (*net.UnixConn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
}

func TestDigestNotSentOnStartup(t *testing.T) {
	h := testHub(t)
	h.cfg.Alerts.DigestTime = "08:00"
	start := time.Date(2026, 10, 1, 22, 0, 0, 0, time.Local)
	h.skipMissedDigest(start)
	if h.store.Meta("lastDigest") != "2026-10-01" {
		t.Fatal("a start after the digest time should skip that day's digest")
	}
	h.skipMissedDigest(time.Date(2026, 10, 2, 7, 55, 0, 0, time.Local))
	if h.store.Meta("lastDigest") != "2026-10-01" {
		t.Fatal("a start before the digest time must leave it due")
	}
	h.digest(time.Date(2026, 10, 2, 8, 1, 0, 0, time.Local))
	if h.store.Meta("lastDigest") != "2026-10-01" {
		t.Fatal("no digest within the grace period after a start")
	}
	h.digest(time.Date(2026, 10, 2, 8, 6, 0, 0, time.Local))
	if h.store.Meta("lastDigest") != "2026-10-02" {
		t.Fatal("digest should go out once the grace period has passed")
	}
}

func TestStuckUnknownAlertsButNotUnderDownAgent(t *testing.T) {
	h := testHub(t)
	now := time.Now()
	h.started = now.Add(-2 * time.Hour)
	h.states["host.alpha.agent"].Status = status.Crit
	h.states["domain.example.org"].LastRun = now.Add(-90 * time.Minute) // ran, but couldn't decide
	h.states["host.alpha.disk"].LastRun = now.Add(-90 * time.Minute)
	h.notify(now)
	if st := h.states["domain.example.org"]; st.Notified != status.Unknown || st.NotifiedAt.IsZero() {
		t.Error("a check unknown since startup should alert")
	}
	if !h.states["host.alpha.disk"].NotifiedAt.IsZero() {
		t.Error("checks under a down agent should stay quiet")
	}
	h2 := testHub(t)
	h2.started = now
	h2.notify(now)
	if !h2.states["domain.example.org"].NotifiedAt.IsZero() {
		t.Error("no unknown alerts right after startup")
	}
}

func TestProbesListsDestinations(t *testing.T) {
	h := testHub(t)
	var b strings.Builder
	if err := Probes(h.cfg, &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"192.0.2.1 25/tcp", "connect, read banner, QUIT", "RCPT TO", "/day", "/h", "destinations"} {
		if !strings.Contains(out, want) {
			t.Errorf("probes output lacks %q:\n%s", want, out)
		}
	}
}

func TestVaultCheck(t *testing.T) {
	h := testHub(t)
	c := h.byID[vaultCheckID]
	if c == nil || c.Secret != "" || c.Interval != time.Minute {
		t.Fatalf("hub.vault = %+v", c)
	}
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if r := vaultStatus(false, start, start.Add(5*time.Minute), 15*time.Minute, "hub"); r.Status != status.Locked || r.Message != "locked for 5m; warns after 15m" {
		t.Errorf("fresh lock = %+v", r)
	}
	if r := vaultStatus(false, start, start.Add(20*time.Minute), 15*time.Minute, "hub"); r.Status != status.Warn ||
		!strings.Contains(r.Message, "locked for 20m") || !strings.Contains(r.Message, "sitescope unlock on hub") {
		t.Errorf("long lock = %+v", r)
	}
	if r := vaultStatus(true, start, start.Add(time.Hour), 15*time.Minute, "hub"); r.Status != status.OK {
		t.Errorf("unlocked = %+v", r)
	}
	st := h.states[vaultCheckID]
	for _, s := range []status.Status{status.Locked, status.Warn} {
		st.Observe(s, "", 0, c.Retries, start)
	}
	if !st.Due(start, time.Hour) {
		t.Error("a long lock after a restart should email")
	}
}

type fakeNotifier struct {
	on   bool
	err  error
	sent []Message
}

func (f *fakeNotifier) Name() string  { return fmt.Sprintf("fake%p", f) }
func (f *fakeNotifier) Enabled() bool { return f.on }
func (f *fakeNotifier) Send(m Message) error {
	f.sent = append(f.sent, m)
	return f.err
}

func TestNotifiers(t *testing.T) {
	h := testHub(t)
	now := time.Now()
	h.started = now.Add(-2 * time.Hour)
	ok, off, failing := &fakeNotifier{on: true}, &fakeNotifier{}, &fakeNotifier{on: true, err: errors.New("down")}
	h.notifiers = []Notifier{ok, off, failing}
	h.states["domain.example.org"].LastRun = now.Add(-90 * time.Minute)
	h.notify(now)
	if len(ok.sent) != 1 || len(off.sent) != 0 || ok.sent[0].Kind != KindChange || ok.sent[0].Worst != status.Unknown {
		t.Fatalf("sent = %+v, disabled = %+v", ok.sent, off.sent)
	}
	if !h.states["domain.example.org"].NotifiedAt.IsZero() {
		t.Error("a failed notifier leaves the change due")
	}
	failing.err = nil
	h.notify(now)
	if len(ok.sent) != 1 || len(failing.sent) != 2 || h.states["domain.example.org"].NotifiedAt.IsZero() {
		t.Errorf("only the failed notifier gets it again, then it is marked: ok %d, failing %d", len(ok.sent), len(failing.sent))
	}
	h.states["domain.example.org"].NotifiedAt = time.Time{}
	h.notify(now)
	if len(ok.sent) != 2 {
		t.Error("after a full delivery the same message goes to everyone again")
	}
}

func TestNoVaultBannerWithoutSecretChecks(t *testing.T) {
	cfg, err := config.Parse([]byte(`{"hub": {"stateDir": "` + t.TempDir() + `", "lockedAfter": "-1s"},
		"hosts": {"hosts": [{"name": "home", "local": true, "os": "fedora", "wireguard": false}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.store.Close()
	if h.byID["hub.vault"] != nil {
		t.Error("lockedAfter negative drops hub.vault")
	}
	w := httptest.NewRecorder()
	h.public(w, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(w.Body.String(), "Vault locked") {
		t.Error("a locked vault pauses nothing here, so no banner")
	}
	n := &fakeNotifier{on: true}
	h.notifiers = []Notifier{n}
	h.startup()
	if len(n.sent) != 0 {
		t.Errorf("no unlock email when nothing needs the vault: %+v", n.sent)
	}
	full := testHub(t)
	full.notifiers = []Notifier{n}
	full.startup()
	if len(n.sent) != 1 || n.sent[0].Kind != KindStartup {
		t.Errorf("the unlock email when checks need the vault: %+v", n.sent)
	}
}
