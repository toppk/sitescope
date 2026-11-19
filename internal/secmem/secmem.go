// Package secmem provides mlocked, non-dumpable buffers outside the Go heap.
package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type Buf struct{ b []byte }

func New(n int) (*Buf, error) {
	if n <= 0 {
		n = 1
	}
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE|mapNoDump)
	if err != nil {
		return nil, fmt.Errorf("secmem: mmap: %w", err)
	}
	if err := unix.Mlock(b); err != nil {
		unix.Munmap(b)
		return nil, fmt.Errorf("secmem: mlock %d bytes (raise LimitMEMLOCK): %w", n, err)
	}
	noDump(b)
	return &Buf{b: b}, nil
}

func (s *Buf) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

func (s *Buf) Destroy() {
	if s == nil || s.b == nil {
		return
	}
	clear(s.b)
	unix.Munlock(s.b)
	unix.Munmap(s.b)
	s.b = nil
}

// Wipe zeroes a heap slice; for buffers we could not keep in locked memory.
func Wipe(b []byte) { clear(b) }

// HardenProcess disables core dumps and, where the system allows it, ptrace attach by non-root users.
func HardenProcess() error {
	if err := noTrace(); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
