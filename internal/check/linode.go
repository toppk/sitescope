package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

type linodeAPI struct {
	base   string
	secret string
}

func (l *linodeAPI) get(ctx context.Context, env *Env, path string, hdr map[string]string, v any) error {
	token, ok := env.Secret(l.secret)
	if !ok {
		return fmt.Errorf("secret %s not in vault", l.secret)
	}
	h := map[string]string{"Authorization": "Bearer " + token}
	for k, val := range hdr {
		h[k] = val
	}
	return getJSON(ctx, env, l.base+path, h, v)
}

type LinodeAccount struct {
	Balance           float64 `json:"balance"`
	BalanceUninvoiced float64 `json:"balance_uninvoiced"`
}

type LinodeNotification struct {
	Type     string `json:"type"`
	Label    string `json:"label"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	When     string `json:"when"`
}

type page[T any] struct {
	Data []T `json:"data"`
}

func (l *linodeAPI) account(cfg *config.Linode) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		var acct LinodeAccount
		if err := l.get(ctx, env, "/account", nil, &acct); err != nil {
			return Unknownf("account: %v", err)
		}
		var notes page[LinodeNotification]
		if err := l.get(ctx, env, "/account/notifications", nil, &notes); err != nil {
			return Unknownf("notifications: %v", err)
		}
		return EvalLinodeAccount(acct, notes.Data, cfg.Uninvoiced)
	}
}

// EvalLinodeAccount: a past-due account gets suspended, so it is critical.
func EvalLinodeAccount(a LinodeAccount, notes []LinodeNotification, uninvoiced Threshold) Result {
	s := uninvoiced.Above(a.BalanceUninvoiced)
	msg := fmt.Sprintf("balance $%.2f, accrued this month $%.2f", a.Balance, a.BalanceUninvoiced)
	for _, n := range notes {
		switch n.Type {
		case "payment_due", "ticket_abuse":
			s = Crit
			msg += "; " + n.Type + ": " + firstNonEmpty(n.Message, n.Label)
		case "ticket_important":
			s = Worst(s, Warn)
			msg += "; " + n.Type + ": " + firstNonEmpty(n.Label, n.Message)
		}
	}
	if a.Balance > 0 {
		s = Worst(s, Warn)
		msg = "unpaid " + msg
	}
	return Rated(s, "%s", msg)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

type LinodeTransfer struct {
	Billable float64 `json:"billable"`
	Quota    float64 `json:"quota"`
	Used     float64 `json:"used"`
}

func (l *linodeAPI) transfer(cfg *config.Linode) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		var t LinodeTransfer
		if err := l.get(ctx, env, "/account/transfer", nil, &t); err != nil {
			return Unknownf("%v", err)
		}
		return EvalTransfer(t, cfg.Transfer)
	}
}

func EvalTransfer(t LinodeTransfer, th Threshold) Result {
	if t.Quota <= 0 {
		return Unknownf("no transfer quota reported")
	}
	pct := 100 * t.Used / t.Quota
	s := th.Above(pct)
	if t.Billable > 0 {
		s = Worst(s, Warn)
	}
	return Rated(s, "%.0f of %.0f GB (%.0f%%), billable %.0f GB", t.Used, t.Quota, pct, t.Billable)
}

type linodeMaintenance struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	When   string `json:"when"`
	Reason string `json:"reason"`
	Entity struct {
		Label string `json:"label"`
	} `json:"entity"`
}

func (l *linodeAPI) maintenance() func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		var m page[linodeMaintenance]
		if err := l.get(ctx, env, "/account/maintenance", nil, &m); err != nil {
			return Unknownf("maintenance: %v", err)
		}
		var notes page[LinodeNotification]
		if err := l.get(ctx, env, "/account/notifications", nil, &notes); err != nil {
			return Unknownf("notifications: %v", err)
		}
		var items []string
		for _, x := range m.Data {
			if x.Status == "completed" {
				continue
			}
			items = append(items, fmt.Sprintf("%s %s on %s at %s", x.Status, x.Type, x.Entity.Label, x.When))
		}
		for _, n := range notes.Data {
			switch {
			case strings.Contains(n.Type, "maintenance"), strings.Contains(n.Type, "migration"),
				n.Type == "reboot_scheduled", n.Type == "outage":
				items = append(items, fmt.Sprintf("%s: %s %s", n.Type, firstNonEmpty(n.Label, n.Message), n.When))
			}
		}
		if len(items) > 0 {
			return Warnf("%s", strings.Join(items, "; "))
		}
		return Okf("nothing scheduled")
	}
}

type LinodeEvent struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Created string `json:"created"`
	Entity  *struct {
		Label string `json:"label"`
	} `json:"entity"`
}

func (l *linodeAPI) events(cfg *config.Linode) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		since := env.now().UTC().Add(-cfg.EventWindow.D()).Format("2006-01-02T15:04:05")
		filter, _ := json.Marshal(map[string]any{"created": map[string]string{"+gte": since}})
		var ev page[LinodeEvent]
		if err := l.get(ctx, env, "/account/events?page_size=100", map[string]string{"X-Filter": string(filter)}, &ev); err != nil {
			return Unknownf("%v", err)
		}
		return EvalEvents(ev.Data, cfg.EventWindow.D())
	}
}

var notableEvents = map[string]bool{"host_reboot": true, "lassie_reboot": true, "linode_migrate": true,
	"linode_migrate_datacenter": true, "linode_delete": true, "linode_rebuild": true, "linode_resize": true,
	"linode_shutdown": true, "account_update": true, "user_create": true, "password_reset": true, "tfa_disabled": true}

func EvalEvents(events []LinodeEvent, window time.Duration) Result {
	var flagged []string
	for _, e := range events {
		if e.Status == "failed" || notableEvents[e.Action] {
			label := ""
			if e.Entity != nil {
				label = " " + e.Entity.Label
			}
			flagged = append(flagged, fmt.Sprintf("%s%s %s at %s", e.Action, label, e.Status, e.Created))
		}
	}
	if len(flagged) > 0 {
		return Warnf("%s", strings.Join(flagged, "; "))
	}
	return Okf("%d routine events in the last %s", len(events), fmtDuration(window))
}

func (l *linodeAPI) instance(in config.LinodeInstance) func(context.Context, *Env) Result {
	return func(ctx context.Context, env *Env) Result {
		var v struct {
			Label  string `json:"label"`
			Status string `json:"status"`
			Region string `json:"region"`
		}
		if err := l.get(ctx, env, "/linode/instances/"+url.PathEscape(fmt.Sprint(in.ID)), nil, &v); err != nil {
			return Unknownf("%v", err)
		}
		if v.Status != "running" {
			return Critf("%s is %s", v.Label, v.Status)
		}
		return Okf("%s running in %s", v.Label, v.Region)
	}
}
