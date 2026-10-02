package hub

import (
	"html/template"
	"time"

	"github.com/toppk/sitescope/internal/status"
)

var funcs = template.FuncMap{
	"word": func(s status.Status) string {
		return map[status.Status]string{status.OK: "Operational", status.Warn: "Degraded",
			status.Crit: "Outage", status.Unknown: "Unknown", status.Locked: "Locked"}[s]
	},
	"headline": func(s status.Status) string {
		return map[status.Status]string{status.OK: "All systems operational", status.Warn: "Some systems degraded",
			status.Crit: "Major outage", status.Unknown: "Status unknown", status.Locked: "All systems operational"}[s]
	},
	// alarm opens a section by default when something in it needs attention.
	"alarm": func(s status.Status) bool { return s == status.Warn || s == status.Crit },
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("01-02 15:04")
	},
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		d := time.Since(t).Round(time.Second)
		switch {
		case d < time.Minute:
			return d.String() + " ago"
		case d < 48*time.Hour:
			return d.Round(time.Minute).String() + " ago"
		}
		return t.UTC().Format("2006-01-02")
	},
	"dur": every,
	// day is a 30-day strip cell; days without history are blank.
	"day": func(s status.Status) string {
		if s == status.Locked {
			return "none"
		}
		return s.String()
	},
}

var templates = template.Must(template.New("").Funcs(funcs).Parse(`
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">{{end}}
<title>{{.Title}}</title>
<link rel="icon" href="/static/logo.png">
<link rel="stylesheet" href="/static/style.css">
<script src="/static/theme.js"></script>
<script src="/static/app.js" defer></script>
</head><body>
<header class="masthead"><div class="masthead-bar">
<a class="brand" href="/"><img src="/static/logo.png" alt=""><span class="brand-name">sitescope</span><span class="brand-tag">{{.Title}}</span></a>
<nav class="topnav" aria-label="Site">
<a href="/"{{if eq .Page "status"}} aria-current="page"{{end}}>Status</a>
<a href="/detail"{{if eq .Page "detail"}} aria-current="page"{{end}}>Detail</a>
{{if .Docs}}<a href="{{.Docs}}">Docs</a>{{end}}
<button class="theme-toggle" type="button" aria-label="Switch between light and dark" title="Light / dark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="12" r="4.5"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg></button>
</nav></div><div class="horizon"></div></header>
<main>{{end}}

{{define "foot"}}</main>
<footer><span>sitescope</span>{{if .Docs}}<a href="{{.Docs}}">Documentation</a>{{end}}<span>Updated {{.Now}}</span>{{if .Refresh}}<span>refreshes every {{.Refresh}}s</span>{{end}}</footer>
</body></html>{{end}}

{{define "overall"}}<section class="card overall {{.Overall}}"><span class="dot big"></span><div>
<div class="headline">{{headline .Overall}}</div>{{if .Summary}}<div class="sub">{{.Summary}}</div>{{end}}</div></section>
{{if .Locked}}<div class="banner">Vault locked: checks that need credentials are paused.</div>{{end}}{{end}}

{{define "item"}}<div class="item {{.Status}}"><span class="dot"></span><span class="name">{{.Label}}</span><span class="word">{{word .Status}}</span></div>{{end}}

{{define "public"}}{{template "head" .}}
{{template "overall" .}}
{{range .Lights}}{{if .Grouped}}<div class="card svc {{.Status}}"><div class="svc-row"><span class="dot"></span><span class="name">{{.Name}}</span><span class="word">{{word .Status}}</span></div></div>
{{else}}<details class="card svc {{.Status}}" id="{{.ID}}"{{if alarm .Status}} open{{end}}>
<summary><span class="dot"></span><span class="name">{{.Name}}</span><span class="count">{{.OK}}/{{.Total}}</span><span class="word">{{word .Status}}</span></summary>
<div class="svc-body">{{range .Groups}}{{if eq (len .Items) 1}}{{template "item" index .Items 0}}
{{else}}<details class="grp {{.Status}}" id="{{.ID}}"{{if alarm .Status}} open{{end}}>
<summary><span class="dot"></span><span class="name">{{.Name}}</span><span class="count">{{.OK}}/{{.Total}}</span><span class="word">{{word .Status}}</span></summary>
{{range .Items}}{{template "item" .}}{{end}}</details>
{{end}}{{end}}</div></details>
{{end}}{{end}}
{{template "foot" .}}{{end}}

{{define "strip"}}<div class="strip" title="last 30 days, oldest first">{{range .}}<i class="{{day .}}"></i>{{end}}</div>{{end}}

{{define "vis"}}{{if eq .Vis "public"}}public as &ldquo;{{.PublicName}}&rdquo; under {{.Service}}{{else if eq .Vis "grouped"}}grouped into {{.Service}}{{else}}private{{end}}{{end}}

{{define "row"}}<div class="row {{.Status}}"><span class="dot"></span><div><a href="/detail/check?id={{.ID}}">{{.Name}}</a>{{if .Retrying}} &middot; retrying {{.Retrying}}/{{.Retries}} ({{.Pending}}){{end}}</div>
<div class="msg">{{.Message}}</div>
<div class="meta">{{.Status}} since {{ts .Since}} &middot; checked {{ago .LastRun}} &middot; every {{dur .Interval}} &middot; {{.TookMS}} ms &middot; {{template "vis" .}}</div>
{{template "strip" .Days}}</div>{{end}}

{{define "detail"}}{{template "head" .}}
{{template "overall" .}}
{{range .Areas}}<details class="card svc {{.Status}}" id="{{.ID}}"{{if alarm .Status}} open{{end}}>
<summary><span class="dot"></span><span class="name">{{.Name}}</span><span class="count">{{.OK}}/{{.Total}}</span><span class="word">{{word .Status}}</span></summary>
<div class="svc-body">{{range .Groups}}{{if eq (len .Items) 1}}{{template "row" index .Items 0}}
{{else}}<details class="grp {{.Status}}" id="{{.ID}}"{{if alarm .Status}} open{{end}}>
<summary><span class="dot"></span><span class="name">{{.Name}}</span><span class="count">{{.OK}}/{{.Total}}</span><span class="word">{{word .Status}}</span></summary>
{{range .Items}}{{template "row" .}}{{end}}</details>
{{end}}{{end}}</div></details>
{{end}}
{{template "foot" .}}{{end}}

{{define "check"}}{{template "head" .}}
{{with .Row}}<h1><a href="/detail">&larr;</a> {{.Name}}</h1>
<div class="card {{.Status}}"><dl>
<dt>Status</dt><dd><span class="dot"></span> {{.Status}} since {{ts .Since}}{{if .Retrying}}, retrying {{.Retrying}}/{{.Retries}} ({{.Pending}}){{end}}</dd>
<dt>Last result</dt><dd>{{.Message}}</dd>
<dt>Last run</dt><dd>{{ago .LastRun}}, {{.TookMS}} ms</dd>
<dt>Check</dt><dd>{{.ID}} &middot; every {{dur .Interval}}, timeout {{dur .Timeout}}, {{.Retries}} retries {{dur .RetryInterval}} apart</dd>
{{range .Probes}}<dt>Contacts</dt><dd>{{.Dest}} {{.Port}}: {{.What}}{{if gt .Count 1}} (&times;{{.Count}}){{end}}</dd>{{end}}
<dt>Public page</dt><dd>{{template "vis" .}}</dd>
<dt>Notified</dt><dd>{{.Notified}} {{if not .NotifiedAt.IsZero}}at {{ts .NotifiedAt}}{{end}}</dd>
<dt>30 days</dt><dd>{{template "strip" .Days}}</dd>
</dl></div>{{end}}
<p class="label">History</p>
<div class="card table-wrap"><table><tr><th>UTC</th><th>status</th><th>ms</th><th>message</th></tr>
{{range .History}}<tr class="{{.Status}}"><td>{{ts .Time}}</td><td class="st"><span class="dot"></span> {{.Status}}</td><td>{{.TookMS}}</td><td class="m">{{.Message}}</td></tr>{{end}}
</table></div>
{{template "foot" .}}{{end}}
`))
