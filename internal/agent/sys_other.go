//go:build !linux && !freebsd && !openbsd

package agent

import (
	"errors"
	"runtime"
)

// Supported is whether the agent has collectors for this system.
const Supported = false

var collectors = linuxCollectors

var errUnsupported = errors.New("the agent has no collectors for " + runtime.GOOS)

type fsStat struct{ blocks, bfree, bavail, bsize, files, ffree uint64 }

func statfs(string) (fsStat, error) { return fsStat{}, errUnsupported }

func freebind(int) error { return errUnsupported }
