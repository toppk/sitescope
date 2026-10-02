package hub

import (
	"embed"
	"fmt"
	"strings"

	"github.com/toppk/sitescope/internal/status"
)

//go:embed static
var static embed.FS

// grp is a collapsible set of rows about one host or target.
type grp[T any] struct {
	ID, Name  string
	Status    status.Status
	OK, Total int
	Items     []T
}

// nest groups xs by key in first-seen order; "" keys stand alone, and locked rows don't count toward status.
func nest[T any](prefix string, xs []T, key func(T) string, st func(T) status.Status) []grp[T] {
	var out []grp[T]
	var sts [][]status.Status
	idx := map[string]int{}
	for _, x := range xs {
		k := key(x)
		i, ok := idx[k]
		if !ok || k == "" {
			i = len(out)
			idx[k] = i
			out = append(out, grp[T]{ID: fmt.Sprintf("%s-%d", prefix, i), Name: k})
			sts = append(sts, nil)
		}
		g := &out[i]
		g.Items = append(g.Items, x)
		g.Total++
		switch s := st(x); s {
		case status.OK:
			g.OK++
			sts[i] = append(sts[i], s)
		case status.Locked:
		default:
			sts[i] = append(sts[i], s)
		}
	}
	for i := range out {
		out[i].Status = status.Locked
		if len(sts[i]) > 0 {
			out[i].Status = status.Worst(sts[i]...)
		}
	}
	return out
}

// summary counts statuses, e.g. "151 checks: 149 ok, 2 warn".
func summary(sts []status.Status) string {
	n := map[status.Status]int{}
	for _, s := range sts {
		n[s]++
	}
	var parts []string
	for _, s := range []status.Status{status.OK, status.Warn, status.Crit, status.Unknown, status.Locked} {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	return fmt.Sprintf("%d checks: %s", len(sts), strings.Join(parts, ", "))
}
