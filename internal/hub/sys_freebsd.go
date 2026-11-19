package hub

import "golang.org/x/sys/unix"

const ioctlGetTermios, ioctlSetTermios = unix.TIOCGETA, unix.TIOCSETA

func sockPeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
