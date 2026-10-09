package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/status"
)

func TestNtfy(t *testing.T) {
	type push struct{ title, prio, tag, click, auth, body string }
	var got []push
	fail := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail > 0 {
			fail--
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got = append(got, push{r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Tags"), r.Header.Get("Click"),
			r.Header.Get("Authorization"), string(b)})
	}))
	defer srv.Close()
	n := &Ntfy{cfg: config.Ntfy{Enabled: true}, url: srv.URL + "/secret-topic", token: "tk", host: "hub1",
		link: "https://status.example.org/", http: srv.Client()}
	change := func(cs ...Change) Message { return Message{Kind: KindChange, Changes: cs} }
	www := func(from, to status.Status) Change { return Change{"http.www", "HTTP www", from, to} }

	if err := n.Send(change(www(status.OK, status.Warn))); err != nil || len(got) != 0 {
		t.Errorf("warn is left to email: %v %+v", err, got)
	}
	n.Send(Message{Kind: KindDigest, Subject: "daily digest"})
	if len(got) != 0 {
		t.Error("digests are not pushed")
	}
	fail = 2
	if err := n.Send(change(www(status.OK, status.Crit), Change{"dns.a", "DNS a", status.Crit, status.OK})); err != nil {
		t.Fatalf("retried past two failures: %v", err)
	}
	want := push{"sitescope hub1", "high", "rotating_light", "https://status.example.org/detail", "Bearer tk", "1 crit, 1 recovered"}
	if len(got) != 1 || got[0] != want {
		t.Errorf("push = %+v, want %+v", got, want)
	}
	n.cfg.Min, n.cfg.Details = "warn", true
	n.Send(change(www(status.Crit, status.Warn)))
	if p := got[len(got)-1]; p.body != "1 warn\nHTTP www" || p.prio != "default" {
		t.Errorf("min warn with details = %+v", p)
	}

	srv.Close()
	err := n.Send(change(www(status.OK, status.Crit)))
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("a failure keeps the topic out of the error: %v", err)
	}
	if (&Ntfy{cfg: config.Ntfy{Enabled: true}}).Enabled() {
		t.Error("without SITESCOPE_NTFY_URL ntfy is off")
	}
}
