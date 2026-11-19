package hub

import "golang.org/x/sys/unix"

const ioctlGetTermios, ioctlSetTermios = unix.TIOCGETA, unix.TIOCSETA

// sockPeerUID reads struct sockpeercred {uid, gid, pid}, 12 bytes, through the 16-byte Timeval getter,
// the libc-backed getsockopt x/sys/unix offers that's large enough; uid is the low half of Sec.
func sockPeerUID(fd int) (int, error) {
	tv, err := unix.GetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(uint32(tv.Sec)), nil
}
