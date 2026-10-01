package hub

import (
	"runtime/debug"
	"sync"

	"github.com/toppk/sitescope/internal/vault"
)

// Vault holds the unlocked secrets in memory for the running hub.
type Vault struct {
	path     string
	mu       sync.RWMutex
	s        *vault.Secrets
	onChange func()
}

func (v *Vault) Unlock(pass []byte) error {
	s, err := vault.Load(v.path, pass)
	if err != nil {
		return err
	}
	v.mu.Lock()
	old := v.s
	v.s = s
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
