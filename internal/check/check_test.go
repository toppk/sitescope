package check

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/toppk/sitescope/internal/config"
	"github.com/toppk/sitescope/internal/report"
)

func TestThresholds(t *testing.T) {
	th := Threshold{Warn: 80, Crit: 90}
	for v, want := range map[float64]Status{10: OK, 79.9: OK, 80: Warn, 89: Warn, 90: Crit, 100: Crit} {
		if got := th.Above(v); got != want {
			t.Errorf("Above(%v) = %v, want %v", v, got, want)
		}
	}
	days := Threshold{Warn: 20, Crit: 7}
	for v, want := range map[float64]Status{60: OK, 20: Warn, 8: Warn, 7: Crit, 0: Crit} {
		if got := days.Below(v); got != want {
			t.Errorf("Below(%v) = %v, want %v", v, got, want)
		}
	}
	if (Threshold{Crit: 5}).Above(100) != Crit || (Threshold{Warn: 5}).Above(100) != Warn {
		t.Error("single-bound thresholds")
	}
	if got := (Threshold{Warn: 1}).Or(Threshold{Warn: 2, Crit: 3}); got != (Threshold{Warn: 1, Crit: 3}) {
		t.Errorf("Or = %v", got)
	}
	if Worst(OK, Unknown, Warn, Locked) != Warn || Worst(Locked) != OK {
		t.Error("Worst")
	}
}

func TestBuildFromConfig(t *testing.T) {
	cfg, err := config.Load("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	checks, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]*Check{}
	for _, c := range checks {
		ids[c.ID] = c
		if c.Interval <= 0 || c.Timeout <= 0 || c.Timeout > c.Interval {
			t.Errorf("%s: interval %v timeout %v", c.ID, c.Interval, c.Timeout)
		}
	}
	for _, id := range []string{
		"dns.primary", "dns.soa.example.org.alpha.v4", "dns.soa.example.net.alpha.v6", "dns.delegation.example.org",
		"dns.resolve.da.example.org", "domain.example.org", "tls.da.example.org.https.443.v6",
		"tls.da.example.org.smtp.25.v4", "http.portal", "mail.banner.alpha.v4", "mail.openrelay.alpha.v4",
		"mail.blocklist.192.0.2.1", "host.alpha.agent", "host.alpha.postfix", "host.alpha.knot", "host.bravo.knot",
		"host.alpha.reboot", "linode.account", "linode.instance.alpha", "cloudflare.records.example.org",
	} {
		if ids[id] == nil {
			t.Errorf("missing check %s", id)
		}
	}
	if ids["host.bravo.postfix"] != nil {
		t.Error("postfix check on a host without postfix")
	}
	if ids["host.alpha.disk"].DependsOn != "host.alpha.agent" || ids["host.alpha.disk"].Retries != 0 {
		t.Error("derived host check should depend on the agent poll and not retry itself")
	}
	if ids["linode.account"].Secret != "linode_token" || ids["cloudflare.records.example.org"].Secret != "cloudflare_token" {
		t.Error("credentialed checks must name their vault secret")
	}
	if ids["domain.example.org"].Interval != 12*time.Hour || ids["http.portal"].Interval != time.Minute {
		t.Error("section default intervals")
	}
	if ids["host.alpha.reboot"].Area != "hygiene" || ids["host.alpha.postfix"].Area != "mail" {
		t.Error("areas")
	}
}

func rep() *report.Report {
	return &report.Report{
		CPUs: 1, Load: [3]float64{0.1, 0.5, 0.2},
		Memory: report.Memory{TotalKB: 1000, AvailableKB: 50, SwapTotalKB: 512, SwapFreeKB: 512},
		Disks:  []report.Disk{{Mount: "/", UsedPct: 85}, {Mount: "/boot", UsedPct: 10, InodesPct: 95}},
	}
}

func TestHostEvals(t *testing.T) {
	r := rep()
	if got := EvalDisk(r, Threshold{Warn: 80, Crit: 90}); got.Status != Crit || !strings.Contains(got.Message, "inodes 95%") {
		t.Errorf("disk = %+v", got)
	}
	if got := EvalMemory(r, Threshold{Warn: 90, Crit: 97}); got.Status != Warn {
		t.Errorf("memory = %+v", got)
	}
	if got := EvalSwap(r, Threshold{Warn: 50}); got.Status != OK {
		t.Errorf("swap = %+v", got)
	}
	r.Load[1] = 3
	if got := EvalLoad(r, Threshold{Warn: 2, Crit: 4}); got.Status != Warn {
		t.Errorf("load = %+v", got)
	}
	r.FailedUnits = []string{"acme-order-renew-x.service"}
	if got := EvalUnits(r); got.Status != Warn {
		t.Errorf("units = %+v", got)
	}
	r.System = report.System{Booted: "/nix/store/a", Current: "/nix/store/b"}
	if got := EvalReboot(r); got.Status != OK {
		t.Errorf("config-only change should not need a reboot: %+v", got)
	}
	r.System.RebootNeeded = true
	if got := EvalReboot(r); got.Status != Warn {
		t.Errorf("reboot = %+v", got)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r.System.NixpkgsDate = "20260825"
	if got := EvalNixpkgs(r, now, Threshold{Warn: 30, Crit: 90}); got.Status != Warn {
		t.Errorf("nixpkgs 37 days = %+v", got)
	}
	r.System.NixpkgsDate = ""
	if got := EvalNixpkgs(r, now, Threshold{Warn: 30}); got.Status != Unknown {
		t.Errorf("nixpkgs without date = %+v", got)
	}
}

func TestWireGuard(t *testing.T) {
	now := time.Unix(100000, 0)
	r := &report.Report{WireGuard: []report.WGPeer{
		{PublicKey: "KEY1=", LatestHandshake: 100000 - 30},
		{PublicKey: "KEY2=", LatestHandshake: 100000 - 700},
		{PublicKey: "KEY3=", LatestHandshake: 0},
	}}
	names := map[string]string{"KEY1=": "bravo", "KEY2=": "charlie", "KEY3=": "delta"}
	th := Threshold{Warn: 600, Crit: 3600}
	if got := EvalWireGuard(r, now, th, names, nil); got.Status != Crit || !strings.Contains(got.Message, "delta never") {
		t.Errorf("wg = %+v", got)
	}
	if got := EvalWireGuard(r, now, th, names, []string{"delta"}); got.Status != Warn || !strings.Contains(got.Message, "charlie 11m ago") {
		t.Errorf("wg ignoring delta = %+v", got)
	}
}

func TestQueueAndKnot(t *testing.T) {
	size, age := Threshold{Warn: 20, Crit: 200}, Threshold{Warn: 3600, Crit: 14400}
	r := &report.Report{Postfix: &report.Postfix{}}
	if got := EvalQueue(r, size, age); got.Status != OK {
		t.Errorf("empty queue = %+v", got)
	}
	r.Postfix = &report.Postfix{Messages: 3, OldestAgeSec: 5 * 3600}
	if got := EvalQueue(r, size, age); got.Status != Crit {
		t.Errorf("old queue = %+v", got)
	}

	exp := Threshold{Warn: 14 * 86400, Crit: 3 * 86400}
	r.Knot = []report.Zone{
		{Name: "example.org", Serial: 1, ExpiresInSec: 27 * 86400},
		{Name: "example.net", Serial: 1, ExpiresInSec: 10 * 86400},
	}
	if got := EvalKnot(r, exp, []string{"example.org", "example.net."}); got.Status != Warn {
		t.Errorf("knot expiring = %+v", got)
	}
	if got := EvalKnot(r, exp, []string{"example.com"}); got.Status != Crit || !strings.Contains(got.Message, "example.com missing") {
		t.Errorf("knot missing zone = %+v", got)
	}
	r.Knot[0].Serial = 0
	if got := EvalKnot(r, exp, nil); got.Status != Crit {
		t.Errorf("knot unloaded = %+v", got)
	}
}

func TestFromReportStaleAndErrors(t *testing.T) {
	env := &Env{Reports: &Reports{}, Now: func() time.Time { return time.Unix(1000, 0) }}
	run := fromReport("h", "disks", time.Minute, func(*report.Report, time.Time) Result { return Okf("fine") })
	if got := run(context.Background(), env); got.Status != Unknown {
		t.Errorf("no report = %+v", got)
	}
	env.Reports.Put("h", &report.Report{}, time.Unix(900, 0))
	if got := run(context.Background(), env); got.Status != Unknown || !strings.Contains(got.Message, "ago") {
		t.Errorf("stale = %+v", got)
	}
	env.Reports.Put("h", &report.Report{Errors: map[string]string{"disks": "boom"}}, time.Unix(990, 0))
	if got := run(context.Background(), env); got.Status != Warn {
		t.Errorf("collector error = %+v", got)
	}
	env.Reports.Put("h", &report.Report{}, time.Unix(990, 0))
	if got := run(context.Background(), env); got.Status != OK {
		t.Errorf("fresh = %+v", got)
	}
}

func TestDNSComparisons(t *testing.T) {
	if CompareSerial(5, 5).Status != OK || CompareSerial(4, 5).Status != Warn {
		t.Error("serial")
	}
	want := []string{"da.example.org", "ne.example.org"}
	if CompareDelegation([]string{"da.example.org", "ne.example.org"}, want, "a.tld").Status != OK {
		t.Error("delegation ok")
	}
	if CompareDelegation([]string{"da.example.org"}, want, "a.tld").Status != Crit {
		t.Error("delegation missing")
	}
	if CompareDelegation([]string{"da.example.org", "ne.example.org", "old.example.com"}, want, "a.tld").Status != Warn {
		t.Error("delegation extra")
	}
	if CompareDelegation(nil, want, "a.tld").Status != Crit {
		t.Error("delegation none")
	}
	if CompareAddrs([]string{"2001:db8:0::1", "192.0.2.1"}, []string{"192.0.2.1", "2001:db8::1"}).Status != OK {
		t.Error("addrs should compare normalized and unordered")
	}
	if CompareAddrs([]string{"192.0.2.9"}, []string{"192.0.2.1"}).Status != Crit {
		t.Error("addrs mismatch")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	days := Threshold{Warn: 45, Crit: 14}
	cases := map[time.Time]Status{
		now.AddDate(1, 0, 0):  OK,
		now.AddDate(0, 0, 40): Warn,
		now.AddDate(0, 0, 10): Crit,
		now.AddDate(0, 0, -1): Crit,
	}
	for exp, want := range cases {
		if got := EvalExpiry(exp, now, days, "x"); got.Status != want {
			t.Errorf("expiry %s = %v, want %v", exp.Format("2006-01-02"), got.Status, want)
		}
	}
	var d rdapDomain
	d.Events = append(d.Events, struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	}{"expiration", "2026-11-10T04:00:00Z"})
	if exp, ok := d.Expiry(); !ok || exp.Day() != 10 {
		t.Errorf("rdap expiry = %v %v", exp, ok)
	}
}

func TestMail(t *testing.T) {
	if EvalRelay(554, "relay denied", 554).Status != OK {
		t.Error("554 is the expected refusal")
	}
	if EvalRelay(250, "ok", 554).Status != Crit {
		t.Error("accepted RCPT is an open relay")
	}
	if EvalRelay(450, "try later", 554).Status != Warn {
		t.Error("other refusals warn")
	}
	ip4 := mustAddr("192.0.2.90")
	if got := ReverseName(ip4, "zen.spamhaus.org"); got != "90.2.0.192.zen.spamhaus.org." {
		t.Errorf("reverse v4 = %s", got)
	}
	ip6 := mustAddr("2001:db8::1")
	if got := ReverseName(ip6, "zen.spamhaus.org"); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, ".8.b.d.0.1.0.0.2.zen.spamhaus.org.") {
		t.Errorf("reverse v6 = %s", got)
	}
	if hit, err := listed([]string{"127.0.0.2"}); !hit || err != nil {
		t.Error("127.0.0.2 is listed")
	}
	if _, err := listed([]string{"127.255.255.254"}); err == nil {
		t.Error("127.255.255.254 means the resolver was refused")
	}
}

func TestLinodeAndCloudflare(t *testing.T) {
	if got := EvalLinodeAccount(LinodeAccount{Balance: 0, BalanceUninvoiced: 12}, nil, Threshold{}); got.Status != OK {
		t.Errorf("clean account = %+v", got)
	}
	if got := EvalLinodeAccount(LinodeAccount{Balance: 5}, nil, Threshold{}); got.Status != Warn {
		t.Errorf("unpaid balance = %+v", got)
	}
	if got := EvalLinodeAccount(LinodeAccount{Balance: 5}, []LinodeNotification{{Type: "payment_due", Message: "past due"}}, Threshold{}); got.Status != Crit {
		t.Errorf("payment due = %+v", got)
	}
	tr := Threshold{Warn: 80, Crit: 95}
	if EvalTransfer(LinodeTransfer{Used: 10, Quota: 3000}, tr).Status != OK ||
		EvalTransfer(LinodeTransfer{Used: 2900, Quota: 3000}, tr).Status != Crit ||
		EvalTransfer(LinodeTransfer{Used: 10, Quota: 3000, Billable: 1}, tr).Status != Warn {
		t.Error("transfer")
	}
	if EvalEvents([]LinodeEvent{{Action: "linode_boot", Status: "finished"}}, time.Hour).Status != OK ||
		EvalEvents([]LinodeEvent{{Action: "host_reboot", Status: "finished"}}, time.Hour).Status != Warn {
		t.Error("events")
	}

	p10 := 10
	expected := []config.DNSRecord{
		{Type: "A", Name: "da.example.org", Content: "192.0.2.1"},
		{Type: "MX", Name: "example.org", Content: "da.example.org.", Priority: &p10},
		{Type: "TXT", Name: "example.org", Content: `"v=spf1 mx ~all"`},
	}
	actual := []config.DNSRecord{
		{Type: "A", Name: "da.example.org", Content: "192.0.2.1"},
		{Type: "MX", Name: "example.org", Content: "da.example.org", Priority: &p10},
		{Type: "TXT", Name: "example.org", Content: "v=spf1 mx ~all"},
		{Type: "A", Name: "www.example.org", Content: "192.0.2.50"},
	}
	if got := CompareRecords(actual, expected, nil); got.Status != OK {
		t.Errorf("records = %+v", got)
	}
	drift := append(actual, config.DNSRecord{Type: "A", Name: "da.example.org", Content: "192.0.2.66"})
	if got := CompareRecords(drift, expected, nil); got.Status != Warn || !strings.Contains(got.Message, "192.0.2.66") {
		t.Errorf("extra record = %+v", got)
	}
	if got := CompareRecords(actual[1:], expected, nil); got.Status != Crit {
		t.Errorf("missing record = %+v", got)
	}
	watch := []config.DNSRecord{{Type: "A", Name: "www.example.org"}}
	if got := CompareRecords(actual, expected, watch); got.Status != Warn {
		t.Errorf("watched name with no expected records = %+v", got)
	}
}

// fakeDNS serves fixed SOA serials per zone, optionally without the aa flag.
func fakeDNS(t *testing.T, serial uint32, aa bool) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = aa
		soa, _ := dns.NewRR(q.Question[0].Name + " 3600 IN SOA ns. host. 1 7200 3600 1209600 3600")
		soa.(*dns.SOA).Serial = serial
		m.Answer = []dns.RR{soa}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestSOACheck(t *testing.T) {
	ctx := context.Background()
	primary := fakeDNS(t, 2026100102, true)
	same := fakeDNS(t, 2026100102, true)
	behind := fakeDNS(t, 2026100101, true)
	notAA := fakeDNS(t, 2026100102, false)
	if got := soaCheck("example.org", same, primary, &serials{})(ctx, nil); got.Status != OK {
		t.Errorf("in sync = %+v", got)
	}
	if got := soaCheck("example.org", behind, primary, &serials{})(ctx, nil); got.Status != Warn {
		t.Errorf("behind = %+v", got)
	}
	if got := soaCheck("example.org", notAA, primary, &serials{})(ctx, nil); got.Status != Crit {
		t.Errorf("no aa = %+v", got)
	}
	if got := primaryCheck(primary, []string{"example.org", "example.net"})(ctx, nil); got.Status != OK {
		t.Errorf("primary = %+v", got)
	}
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if got := soaCheck("example.org", "127.0.0.1:9", primary, &serials{})(tctx, nil); got.Status != Crit {
		t.Errorf("dead server = %+v", got)
	}
}

// fakeSMTP answers the open-relay probe with the given RCPT reply.
func fakeSMTP(t *testing.T, rcptReply string) (string, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("220 mx.example.org ESMTP\r\n"))
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					cmd := strings.ToUpper(string(buf[:n]))
					switch {
					case strings.HasPrefix(cmd, "EHLO"):
						c.Write([]byte("250-mx.example.org\r\n250 8BITMIME\r\n"))
					case strings.HasPrefix(cmd, "MAIL"):
						c.Write([]byte("250 ok\r\n"))
					case strings.HasPrefix(cmd, "RCPT"):
						c.Write([]byte(rcptReply + "\r\n"))
					case strings.HasPrefix(cmd, "QUIT"):
						c.Write([]byte("221 bye\r\n"))
						return
					}
				}
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func TestSMTPProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := &config.OpenRelay{Helo: "probe.example", From: "a@example.com", To: "b@example.net", Expect: 554}
	ip, port := fakeSMTP(t, "554 5.7.1 Relay access denied")
	if got := openRelayCheck(ip, port, cfg)(ctx, nil); got.Status != OK {
		t.Errorf("closed relay = %+v", got)
	}
	ip, port = fakeSMTP(t, "250 2.1.5 Ok")
	if got := openRelayCheck(ip, port, cfg)(ctx, nil); got.Status != Crit {
		t.Errorf("open relay = %+v", got)
	}
	got := bannerCheck(ip, config.MailServer{Port: port, Expect: "mx.example.org"}, Threshold{Warn: 3})(ctx, nil)
	if got.Status != OK {
		t.Errorf("banner = %+v", got)
	}
	got = bannerCheck(ip, config.MailServer{Port: port, Expect: "other.example"}, Threshold{Warn: 3})(ctx, nil)
	if got.Status != Warn {
		t.Errorf("banner mismatch = %+v", got)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func counterReport(at time.Time, boot int64, cpuBusy, cpuIdle float64, psiUS, oom, swapIn, ioMS, rx uint64) *report.Report {
	return &report.Report{Time: at, Counters: &report.Counters{
		BootTime: boot,
		CPU:      []report.CPU{{User: cpuBusy, Idle: cpuIdle}},
		Pressure: map[string]report.PSI{"memory": {SomeTotalUS: psiUS}, "io": {SomeTotalUS: psiUS / 2}, "cpu": {}},
		VM:       report.VMStat{OOMKill: oom, PswpIn: swapIn},
		Disks:    []report.DiskIO{{Device: "sda", IOTimeMS: ioMS, WrittenBytes: rx}},
		Net:      []report.NetIO{{Device: "eth0", RxBytes: rx}},
	}}
}

func TestRates(t *testing.T) {
	t0 := time.Unix(1790000000, 0)
	a := counterReport(t0, 1, 100, 900, 0, 0, 0, 0, 0)
	// 300s later: 270 of 300 CPU-seconds busy, memory stalled 60s, 3000 pages swapped in, disk busy 150s
	b := counterReport(t0.Add(5*time.Minute), 1, 370, 930, 60e6, 0, 3000, 150000, 3e8)
	r, err := ComputeRates(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.CPUBusy != 90 || r.PSISome["memory"] != 20 || r.SwapIn != 10 || r.Disks[0].BusyPct != 50 || r.Net[0].RxBps != 1e6 {
		t.Fatalf("rates = %+v", r)
	}
	if got := EvalCPU(r, Threshold{Warn: 85, Crit: 95}); got.Status != Warn || !strings.Contains(got.Message, "90% busy over 5m") {
		t.Errorf("cpu = %+v", got)
	}
	if got := EvalMemPressure(r, Threshold{Warn: 10, Crit: 30}, Threshold{Warn: 100, Crit: 1000}); got.Status != Warn {
		t.Errorf("memory pressure = %+v", got)
	}
	b.Counters.VM.OOMKill = 2
	r, _ = ComputeRates(a, b)
	if got := EvalMemPressure(r, Threshold{Warn: 10, Crit: 30}, Threshold{}); got.Status != Crit || !strings.HasPrefix(got.Message, "2 OOM kill") {
		t.Errorf("OOM kills are critical: %+v", got)
	}
	if got := EvalDiskIO(r, Threshold{Warn: 80, Crit: 95}, Threshold{Warn: 25, Crit: 50}); got.Status != OK {
		t.Errorf("disk io = %+v", got)
	}
	if got := EvalNetwork(r, Threshold{Warn: 1, Crit: 10}, Threshold{}); got.Status != OK || !strings.Contains(got.Message, "eth0 in 8.00") {
		t.Errorf("network = %+v", got)
	}
	if _, err := ComputeRates(&report.Report{Time: t0}, b); err == nil {
		t.Error("reports without counters can't give rates")
	}
}

func TestReportsWindow(t *testing.T) {
	var rs Reports
	t0 := time.Unix(1790000000, 0)
	for i := range 12 {
		at := t0.Add(time.Duration(i) * time.Minute)
		rs.Put("a", counterReport(at, 1, 0, 0, 0, 0, 0, 0, 0), at)
	}
	old, cur := rs.Window("a", 5*time.Minute)
	if cur.Time.Sub(old.Time) != 5*time.Minute {
		t.Errorf("window = %s", cur.Time.Sub(old.Time))
	}
	at := t0.Add(12 * time.Minute)
	rs.Put("a", counterReport(at, 2, 0, 0, 0, 0, 0, 0, 0), at)
	if old, cur := rs.Window("a", 5*time.Minute); old != cur {
		t.Error("a reboot starts the history over")
	}
	u := &report.Report{Units: []report.UnitMem{{Unit: "sitescope.service", Bytes: 60 << 20, MaxBytes: 64 << 20}, {Unit: "knot.service", Bytes: 80 << 20}}}
	if got := EvalUnitMemory(u, Threshold{Warn: 85, Crit: 95}); got.Status != Warn || !strings.Contains(got.Message, "sitescope 60 MiB of 64 MiB") {
		t.Errorf("unit memory = %+v", got)
	}
	m := &report.Report{Memory: report.Memory{TotalKB: 1000000, AvailableKB: 400000, CachedKB: 200000}, Units: u.Units}
	if got := EvalMemory(m, Threshold{Warn: 90, Crit: 97}); !strings.Contains(got.Message, "largest: knot 80 MiB, sitescope 60 MiB") {
		t.Errorf("memory = %+v", got)
	}
}
