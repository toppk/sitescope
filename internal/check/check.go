package check

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/toppk/sitescope/internal/report"
)

type Result struct {
	Status  Status        `json:"status"`
	Message string        `json:"message"`
	Took    time.Duration `json:"took"`
	// RetryIn asks for the next run sooner than the interval, e.g. after an API's Retry-After.
	RetryIn time.Duration `json:"-"`
}

func Okf(f string, a ...any) Result   { return Result{Status: OK, Message: fmt.Sprintf(f, a...)} }
func Warnf(f string, a ...any) Result { return Result{Status: Warn, Message: fmt.Sprintf(f, a...)} }
func Critf(f string, a ...any) Result { return Result{Status: Crit, Message: fmt.Sprintf(f, a...)} }
func Unknownf(f string, a ...any) Result {
	return Result{Status: Unknown, Message: fmt.Sprintf(f, a...)}
}

func Rated(s Status, f string, a ...any) Result {
	return Result{Status: s, Message: fmt.Sprintf(f, a...)}
}

type Check struct {
	ID            string
	Name          string
	Area          string
	Interval      time.Duration
	Timeout       time.Duration
	Retries       int
	RetryInterval time.Duration
	// Vault secret the check needs; while locked it reports Locked without running.
	Secret string
	// DependsOn names the check whose result this one reads (an agent poll).
	DependsOn string
	// Offset delays the first run, to spread checks that share an API's rate limit.
	Offset time.Duration
	// Group is the host or target the check is about, for display; "" stands alone.
	Group  string
	Probes []Probe
	Run    func(ctx context.Context, env *Env) Result
}

// Probe is one kind of network contact a run makes, listed by `sitescope probes`.
type Probe struct {
	Dest  string // address or host name
	Port  string // e.g. "25/tcp"
	What  string
	Count int // contacts per run
}

type Env struct {
	HTTP       *http.Client
	Hostname   string
	AgentToken string
	Secret     func(name string) (string, bool)
	Reports    *Reports
	Now        func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Reports caches recent agent reports per host: the latest for the host checks,
// and a few minutes of history so counters can become rates.
type Reports struct {
	mu sync.Mutex
	m  map[string][]reportEntry
}

type reportEntry struct {
	r  *report.Report
	at time.Time
}

// keepReports bounds the history; it must exceed the longest rate window.
const keepReports = 20 * time.Minute

func (r *Reports) Put(host string, rep *report.Report, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string][]reportEntry{}
	}
	h := r.m[host]
	// a reboot resets every counter, so older reports can't be compared
	if n := len(h); n > 0 && bootTime(h[n-1].r) != bootTime(rep) {
		h = nil
	}
	if n := len(h); n > 0 && h[n-1].r.Time.Equal(rep.Time) {
		h = h[:n-1]
	}
	h = append(h, reportEntry{rep, at})
	for len(h) > 1 && at.Sub(h[0].at) > keepReports {
		h = h[1:]
	}
	r.m[host] = h
}

func bootTime(r *report.Report) int64 {
	if r.Counters == nil {
		return 0
	}
	return r.Counters.BootTime
}

func (r *Reports) Get(host string) (*report.Report, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.m[host]
	if len(h) == 0 {
		return nil, time.Time{}
	}
	e := h[len(h)-1]
	return e.r, e.at
}

// Window returns the newest report and the newest one at least d older, or the oldest kept.
func (r *Reports) Window(host string, d time.Duration) (old, cur *report.Report) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.m[host]
	if len(h) == 0 {
		return nil, nil
	}
	cur = h[len(h)-1].r
	old = h[0].r
	for _, e := range h {
		if cur.Time.Sub(e.r.Time) >= d {
			old = e.r
		}
	}
	return old, cur
}

const userAgent = "sitescope/1"
