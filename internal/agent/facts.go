package agent

import (
	"errors"
	"os"
	"strings"

	"github.com/toppk/sitescope/internal/report"
)

// kernel compares the running kernel with the newest under /usr/lib/modules; NixOS uses its generations instead.
func (c *Collector) kernel(r *report.Report) error {
	b, err := os.ReadFile(c.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return err
	}
	k := &report.Kernel{Running: strings.TrimSpace(string(b))}
	ents, err := os.ReadDir(c.path("/usr/lib/modules"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		// a directory left behind by an out-of-tree module has no kernel image
		if _, err := os.Stat(c.path("/usr/lib/modules/" + e.Name() + "/vmlinuz")); err != nil && e.Name() != k.Running {
			continue
		}
		if k.Newest == "" || VersionCompare(e.Name(), k.Newest) > 0 {
			k.Newest = e.Name()
		}
	}
	r.Kernel = k
	return nil
}

// pkgDBs are package databases whose mtime is the last install, update or removal.
var pkgDBs = []struct{ manager, path string }{
	{"rpm", "/usr/lib/sysimage/rpm/rpmdb.sqlite"},
	{"rpm", "/var/lib/rpm/rpmdb.sqlite"},
	{"rpm", "/var/lib/rpm/Packages"},
	{"dpkg", "/var/lib/dpkg/status"},
	{"apk", "/lib/apk/db/installed"},
	{"pacman", "/var/lib/pacman/local"},
}

func (c *Collector) packages(r *report.Report) error {
	for _, db := range pkgDBs {
		if st, err := os.Stat(c.path(db.path)); err == nil {
			r.Packages = &report.Packages{Manager: db.manager, Changed: st.ModTime().Unix()}
			return nil
		}
	}
	return errors.New("no known package database")
}

// VersionCompare orders versions like rpm does: digit runs numerically, letter runs as text, digits above letters.
func VersionCompare(a, b string) int {
	seg := func(s string) (string, string, bool) {
		s = strings.TrimLeftFunc(s, func(r rune) bool { return !isDigit(r) && !isAlpha(r) })
		if s == "" {
			return "", "", false
		}
		f := isAlpha
		if isDigit(rune(s[0])) {
			f = isDigit
		}
		i := strings.IndexFunc(s, func(r rune) bool { return !f(r) })
		if i < 0 {
			i = len(s)
		}
		return s[:i], s[i:], true
	}
	for {
		x, ra, okA := seg(a)
		y, rb, okB := seg(b)
		switch {
		case !okA && !okB:
			return 0
		case !okA:
			return -1
		case !okB:
			return 1
		}
		dx, dy := isDigit(rune(x[0])), isDigit(rune(y[0]))
		switch {
		case dx && !dy:
			return 1
		case !dx && dy:
			return -1
		case dx:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return cmpInt(len(x), len(y))
			}
		}
		if x != y {
			return strings.Compare(x, y)
		}
		a, b = ra, rb
	}
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }
func isAlpha(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}
