//go:build !linux

package agent

import (
	"errors"
	"runtime"
)

// Supported is whether this system has what the collectors read: /proc, /sys and systemd.
const Supported = false

var errUnsupported = errors.New("the agent's collectors need Linux, not " + runtime.GOOS)

type fsStat struct{ blocks, bfree, bavail, bsize, files, ffree uint64 }

func statfs(string) (fsStat, error) { return fsStat{}, errUnsupported }

func freebind(int) error { return errUnsupported }
