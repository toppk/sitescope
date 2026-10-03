package hub

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/toppk/sitescope/internal/check"
	"github.com/toppk/sitescope/internal/status"
	"github.com/toppk/sitescope/internal/vault"
)

// Vault holds the unlocked secrets in memory for the running hub.
type Vault struct {
	path     string
	mu       sync.RWMutex
	s        *vault.Secrets
	since    time.Time // when it was last locked or unlocked
	onChange func()
}

func (v *Vault) Unlock(pass []byte) error {
	s, err := vault.Load(v.path, pass)
	if err != nil {
		return err
	}
	v.mu.Lock()
	old := v.s
	v.s, v.since = s, time.Now()
	v.mu.Unlock()
	old.Destroy()
	// hand scrypt's 32 MiB back to the OS right away
	debug.FreeOSMemory()
	if v.onChange != nil {
		v.onChange()
	}
	return nil
}

func (v *Vault) Lock() {
	v.mu.Lock()
	old := v.s
	if old != nil {
		v.since = time.Now()
	}
	v.s = nil
	v.mu.Unlock()
	clearAuthCache()
	if old != nil {
		old.Destroy()
		if v.onChange != nil {
			v.onChange()
		}
	}
}

func (v *Vault) Unlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.s != nil
}

// State reports whether the vault is unlocked, and since when it has been in that state.
func (v *Vault) State() (bool, time.Time) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.s != nil, v.since
}

func (v *Vault) Get(name string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.s.Get(name)
}

func (v *Vault) With(name string, fn func([]byte)) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.s.With(name, fn)
}

func (v *Vault) Names() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.s.Names()
}

const vaultCheckID = "hub.vault"

func (h *Hub) vaultCheck() *check.Check {
	return &check.Check{ID: vaultCheckID, Name: "Vault unlocked", Area: "hub", Group: "Hub",
		Interval: h.cfg.Hub.Tick.D(), Timeout: 10 * time.Second, RetryInterval: h.cfg.Hub.Tick.D(),
		Run: func(context.Context, *check.Env) check.Result {
			open, since := h.vault.State()
			return vaultStatus(open, since, time.Now(), h.cfg.Hub.LockedAfter.D(), h.cfg.Hub.Hostname)
		}}
}

// vaultStatus is locked (not alerting) at first, and warns once the vault has been locked for after.
func vaultStatus(open bool, since, now time.Time, after time.Duration, host string) check.Result {
	d := now.Sub(since).Truncate(time.Minute)
	ago := every(d)
	if d < time.Minute {
		ago = "under a minute"
	}
	switch {
	case open:
		return check.Okf("unlocked")
	case d >= after:
		return check.Warnf("locked for %s: credentialed checks aren't running; run sitescope unlock on %s", ago, host)
	}
	return check.Result{Status: status.Locked, Message: fmt.Sprintf("locked for %s; warns after %s", ago, every(after))}
}
