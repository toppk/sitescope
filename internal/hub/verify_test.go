package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/toppk/sitescope/internal/check"
)

func TestVerify(t *testing.T) {
	h := testHub(t)
	h.nextWake.Store(time.Now().Unix())
	defer func(v string) { Version = v }(Version)
	Version = "1.4.0+abc1234"
	rec := httptest.NewRecorder()
	h.statusJSON(rec, httptest.NewRequest("GET", "/status.json", nil))
	var doc StatusDoc
	json.Unmarshal(rec.Body.Bytes(), &doc)
	checks := 0
	for _, s := range doc.Services {
		checks += len(s.Checks)
	}
	if len(doc.Services) < 2 || checks == 0 {
		t.Fatalf("testdata should have public services and checks: %+v", doc)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /status.json", h.statusJSON)
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	c, err := check.CAClient(ca)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(c *http.Client, want Expect) (string, error) {
		var out bytes.Buffer
		err := Verify(context.Background(), c, srv.URL+"/", want, &out)
		return out.String(), err
	}

	all := Expect{Version: "1.4.0+abc1234", Vault: "locked", Overall: doc.Overall.String(), Services: len(doc.Services), Checks: checks}
	if out, err := verify(c, all); err != nil || strings.Contains(out, "FAIL") {
		t.Errorf("all met = %v\n%s", err, out)
	}
	if out, err := verify(c, Expect{Version: "1.4.0", Services: -1, Checks: -1}); err != nil {
		t.Errorf("the release alone should match = %v\n%s", err, out)
	}
	out, err := verify(c, Expect{Version: "1.3.0+f7e2e67", Vault: "unlocked", Services: len(doc.Services) + 1, Checks: -1})
	if err == nil || strings.Count(out, "FAIL") != 3 || !strings.Contains(out, "FAIL  vault     locked, want unlocked") {
		t.Errorf("three unmet = %v\n%s", err, out)
	}
	if _, err := verify(http.DefaultClient, all); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("without the CA the cert is untrusted = %v", err)
	}
	h.nextWake.Store(time.Now().Add(-time.Hour).Unix())
	if out, err := verify(c, all); err == nil || !strings.Contains(out, "FAIL  healthz   503") {
		t.Errorf("stalled scheduler = %v\n%s", err, out)
	}
}

// Hubs and verify of adjacent releases read each other's /healthz and /status.json.
func TestStatusCompat(t *testing.T) {
	b, err := os.ReadFile("../../testdata/compat/status-1.3.0.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var doc StatusDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("a 1.3.0 field was removed or renamed: %v", err)
	}
	out, _ := json.Marshal(doc)
	var want, got any
	json.Unmarshal(b, &want)
	json.Unmarshal(out, &got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a 1.3.0 field changed shape:\nwant %s\ngot  %s", b, out)
	}

	// /healthz both ways: this hub serves 1.3.0's bytes, and this verify accepts them
	healthz, err := os.ReadFile("../../testdata/compat/healthz-1.3.0.txt")
	if err != nil {
		t.Fatal(err)
	}
	h := testHub(t)
	h.nextWake.Store(time.Now().Unix())
	w := httptest.NewRecorder()
	h.healthz(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 || w.Body.String() != string(healthz) {
		t.Errorf("/healthz = %d %q, want 200 %q", w.Code, w.Body.String(), healthz)
	}
	old := http.NewServeMux()
	old.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write(healthz) })
	old.HandleFunc("GET /status.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(b) })
	srv := httptest.NewServer(old)
	defer srv.Close()
	var vout bytes.Buffer
	if err := Verify(context.Background(), srv.Client(), srv.URL, Expect{Version: "1.3.0", Services: 2, Checks: 1}, &vout); err != nil {
		t.Errorf("verify against a 1.3.0 hub = %v\n%s", err, &vout)
	}
}
