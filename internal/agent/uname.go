package agent

import (
	"strings"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/report"
)

// unameRelease names the system from uname(2), for one without /etc/os-release.
func unameRelease(r *report.Report) error {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return err
	}
	name, rel := unix.ByteSliceToString(u.Sysname[:]), unix.ByteSliceToString(u.Release[:])
	r.OS = &report.OS{ID: strings.ToLower(name), VersionID: rel, Name: name + " " + rel}
	return nil
}
