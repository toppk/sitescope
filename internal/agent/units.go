package agent

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/toppk/sitescope/internal/report"
)

// maxUnits bounds one request's systemctl work.
const maxUnits = 64

var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+\.(service|timer|socket|mount|path|target)$`)

// UnitQuery is the units the hub asks about in /v1/report?unit=…&userUnit=….
type UnitQuery struct{ System, User []string }

func (q UnitQuery) Empty() bool { return len(q.System)+len(q.User) == 0 }

func (q UnitQuery) Validate() error {
	if len(q.System)+len(q.User) > maxUnits {
		return fmt.Errorf("at most %d units", maxUnits)
	}
	for _, u := range slices.Concat(q.System, q.User) {
		if !unitName.MatchString(u) {
			return fmt.Errorf("bad unit name %q", u)
		}
	}
	return nil
}

// Units reports the queried units' state; a failing manager is an error for its units only.
func (c *Collector) Units(ctx context.Context, q UnitQuery) ([]report.UnitState, error) {
	out := []report.UnitState{}
	var errs []string
	for _, m := range []struct {
		user  bool
		units []string
	}{{false, q.System}, {true, q.User}} {
		if len(m.units) == 0 {
			continue
		}
		st, err := c.showUnits(ctx, m.user, m.units)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, st...)
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func (c *Collector) showUnits(ctx context.Context, user bool, units []string) ([]report.UnitState, error) {
	show := func(props string, names []string) ([]map[string]string, error) {
		args := []string{"show", "--timestamp=unix", "--property=" + props}
		if user {
			args = append([]string{"--user"}, args...)
		}
		out, err := run(ctx, c.Cfg.Systemctl, append(append(args, "--"), names...)...)
		if err != nil {
			return nil, err
		}
		return ParseShow(out), nil
	}
	blocks, err := show("Id,LoadState,ActiveState,SubState,Result,Unit,LastTriggerUSec,NextElapseUSecRealtime", units)
	if err != nil {
		return nil, err
	}
	if len(blocks) != len(units) {
		return nil, fmt.Errorf("systemctl show: %d units, want %d", len(blocks), len(units))
	}
	out := make([]report.UnitState, len(units))
	var services []string
	for i, b := range blocks {
		s := report.UnitState{Unit: units[i], User: user, Load: b["LoadState"], Active: b["ActiveState"], Sub: b["SubState"], Result: b["Result"]}
		if strings.HasSuffix(units[i], ".timer") {
			s.Result = ""
			s.LastRun, s.NextRun = unixStamp(b["LastTriggerUSec"]), unixStamp(b["NextElapseUSecRealtime"])
			if svc := b["Unit"]; unitName.MatchString(svc) {
				s.Service = svc
				services = append(services, svc)
			}
		}
		out[i] = s
	}
	if len(services) == 0 {
		return out, nil
	}
	sb, err := show("Id,ActiveState,Result,ExecMainStatus", services)
	if err != nil || len(sb) != len(services) {
		return out, err
	}
	byID := map[string]map[string]string{}
	for i, b := range sb {
		byID[services[i]] = b
	}
	for i := range out {
		if b, ok := byID[out[i].Service]; ok {
			out[i].Result = b["Result"]
			out[i].Running = b["ActiveState"] == "activating" || b["ActiveState"] == "active"
			out[i].ExitStatus, _ = strconv.Atoi(b["ExecMainStatus"])
		}
	}
	return out, nil
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
