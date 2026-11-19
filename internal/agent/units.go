package agent

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// maxUnits bounds one request's service-manager work.
const maxUnits = 64

// UnitQuery is the units the hub asks about in /v1/report?unit=…&userUnit=….
type UnitQuery struct{ System, User []string }

func (q UnitQuery) Empty() bool { return len(q.System)+len(q.User) == 0 }

func (q UnitQuery) Validate() error {
	if len(q.System)+len(q.User) > maxUnits {
		return fmt.Errorf("at most %d units", maxUnits)
	}
	if len(q.User) > 0 && !userUnits {
		return fmt.Errorf("user units are Linux only")
	}
	for _, u := range slices.Concat(q.System, q.User) {
		if !validUnit(u) {
			return fmt.Errorf("bad unit name %q", u)
		}
	}
	return nil
}

// ParseShow splits systemctl show output into one map per unit.
func ParseShow(out []byte) []map[string]string {
	var blocks []map[string]string
	var cur map[string]string
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			cur = nil
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if cur == nil {
			cur = map[string]string{}
			blocks = append(blocks, cur)
		}
		cur[k] = v
	}
	return blocks
}

// unixStamp reads --timestamp=unix values like "@1791460000"; empty and "n/a" are 0.
func unixStamp(v string) int64 {
	n, _ := strconv.ParseInt(strings.TrimPrefix(v, "@"), 10, 64)
	return n
}
