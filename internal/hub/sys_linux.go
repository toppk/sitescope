package hub

import "golang.org/x/sys/unix"

const ioctlGetTermios, ioctlSetTermios = unix.TCGETS, unix.TCSETS

func sockPeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
