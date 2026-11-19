package agent

import "golang.org/x/sys/unix"

// Supported is whether this system has what the collectors read: /proc, /sys and systemd.
const Supported = true

type fsStat struct{ blocks, bfree, bavail, bsize, files, ffree uint64 }

func statfs(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	return fsStat{st.Blocks, st.Bfree, st.Bavail, uint64(st.Bsize), st.Files, st.Ffree}, nil
}

func freebind(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_FREEBIND, 1) }
