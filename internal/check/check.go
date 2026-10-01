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
	Run       func(ctx context.Context, env *Env) Result
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

// Reports caches the latest agent report per host for the derived host checks.
type Reports struct {
	mu sync.Mutex
	m  map[string]reportEntry
}

type reportEntry struct {
	r  *report.Report
	at time.Time
}

func (r *Reports) Put(host string, rep *report.Report, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]reportEntry{}
	}
	r.m[host] = reportEntry{rep, at}
}

func (r *Reports) Get(host string) (*report.Report, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.m[host]
	return e.r, e.at
}

const userAgent = "sitescope/1"
