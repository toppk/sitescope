package secmem

import "golang.org/x/sys/unix"

const mapNoDump = 0

func noDump(b []byte) { unix.Madvise(b, unix.MADV_DONTDUMP) }

func noTrace() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
