package secmem

import "golang.org/x/sys/unix"

// MAP_CONCEAL keeps the pages out of core dumps.
const mapNoDump = unix.MAP_CONCEAL

func noDump([]byte) {}

// noTrace has nothing to do: kern.global_ptrace=0, the default, already limits ptrace to a process's own children.
func noTrace() error { return nil }
