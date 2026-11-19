package secmem

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const mapNoDump = unix.MAP_NOCORE

func noDump([]byte) {}

// procctl(2) constants from <sys/procctl.h> and <sys/wait.h>; x/sys/unix doesn't define them.
const (
	pPID                = 0
	procTraceCtl        = 7
	procTraceCtlDisable = 2
)

// noTrace turns off ptrace and core dumps, like Linux's PR_SET_DUMPABLE.
func noTrace() error {
	arg := int32(procTraceCtlDisable)
	_, _, e := unix.Syscall6(unix.SYS_PROCCTL, pPID, uintptr(os.Getpid()), procTraceCtl, uintptr(unsafe.Pointer(&arg)), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
