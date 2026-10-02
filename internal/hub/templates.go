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
	"dur": func(d time.Duration) string { return d.String() },
}

const css = `
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e2dd;--ok:#2f9e5b;--warn:#d99a00;--crit:#d23a2f;--unknown:#8a8a85;--locked:#b8b8b2}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#9a9993;--card:#1f1f1d;--line:#33332f;--ok:#3fbf72;--warn:#e6b23a;--crit:#ef5a4f;--unknown:#7d7d78;--locked:#4a4a46}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,sans-serif}
main{max-width:860px;margin:0 auto;padding:20px 16px 40px}h1{font-size:20px;margin:0 0 16px}h2{font-size:15px;margin:24px 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
a{color:inherit}.card{background:var(--card);border:1px solid var(--line);border-radius:10px}
.hero{padding:16px;font-size:17px;font-weight:600;display:flex;gap:10px;align-items:center;margin-bottom:16px}
.dot{width:12px;height:12px;border-radius:50%;flex:none;display:inline-block}.ok{background:var(--ok)}.warn{background:var(--warn)}.crit{background:var(--crit)}.unknown{background:var(--unknown)}.locked{background:var(--locked)}
.banner{padding:10px 14px;margin-bottom:16px;border-left:4px solid var(--warn)}
ul.svc{list-style:none;margin:0;padding:0}ul.svc li{display:flex;align-items:center;gap:10px;padding:12px 16px;border-top:1px solid var(--line)}ul.svc li:first-child{border-top:0}
ul.svc li.sub{padding-left:40px;font-size:14px;border-top-style:dashed}
.lbl{margin-left:auto;color:var(--mut);font-size:14px}footer{color:var(--mut);font-size:13px;margin-top:16px}
.row{display:grid;grid-template-columns:14px 1fr;gap:4px 10px;padding:10px 14px;border-top:1px solid var(--line)}.row:first-child{border-top:0}.row .dot{margin-top:5px}
.msg{grid-column:2;color:var(--mut);font-size:13px;overflow-wrap:anywhere}.meta{grid-column:2;color:var(--mut);font-size:12px}
.strip{grid-column:2;display:flex;gap:2px;margin-top:2px}.strip i{flex:1;height:10px;border-radius:2px;max-width:14px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px 8px;border-top:1px solid var(--line);text-align:left;vertical-align:top}td.m{overflow-wrap:anywhere}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:14px;margin:0}dt{color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}
`

var templates = template.Must(template.New("").Funcs(funcs).Parse(`
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">{{end}}
<title>{{.Title}}</title><style>` + css + `</style></head><body><main>{{end}}
{{define "foot"}}<footer>Updated {{.Now}}</footer></main></body></html>{{end}}
{{define "locked"}}{{if .Locked}}<div class="card banner">Vault locked: checks that need credentials are paused.</div>{{end}}{{end}}

{{define "public"}}{{template "head" .}}
<h1>{{.Title}}</h1>
<div class="card hero"><span class="dot {{.Overall}}"></span>{{headline .Overall}}</div>
{{template "locked" .}}
<div class="card"><ul class="svc">{{range .Lights}}<li><span class="dot {{.Status}}"></span>{{.Name}}<span class="lbl">{{word .Status}}</span></li>
{{range .Items}}<li class="sub"><span class="dot {{.Status}}"></span>{{.Label}}<span class="lbl">{{word .Status}}</span></li>{{end}}{{end}}</ul></div>
{{template "foot" .}}{{end}}

{{define "vis"}}{{if eq .Vis "public"}}public as &ldquo;{{.PublicName}}&rdquo; under {{.Service}}{{else if eq .Vis "grouped"}}grouped into {{.Service}}{{else}}private{{end}}{{end}}

{{define "strip"}}<div class="strip" title="last 30 days, oldest first">{{range .}}<i class="{{.}}"></i>{{end}}</div>{{end}}

{{define "detail"}}{{template "head" .}}
<h1>{{.Title}} &middot; detail</h1>
<div class="card hero"><span class="dot {{.Overall}}"></span>{{headline .Overall}}</div>
{{template "locked" .}}
{{range .Groups}}<h2>{{.Name}}</h2><div class="card">{{range .Rows}}
<div class="row"><span class="dot {{.Status}}"></span><div><a href="/detail/check?id={{.ID}}">{{.Name}}</a>{{if .Retrying}} &middot; retrying {{.Retrying}}/{{.Retries}} ({{.Pending}}){{end}}</div>
<div class="msg">{{.Message}}</div>
<div class="meta">{{.Status}} since {{ts .Since}} &middot; checked {{ago .LastRun}} &middot; {{.TookMS}} ms &middot; {{template "vis" .}}</div>
{{template "strip" .Days}}</div>{{end}}</div>{{end}}
{{template "foot" .}}{{end}}

{{define "check"}}{{template "head" .}}
{{with .Row}}<h1><a href="/detail">&larr;</a> {{.Name}}</h1>
<div class="card"><dl>
<dt>Status</dt><dd><span class="dot {{.Status}}"></span> {{.Status}} since {{ts .Since}}{{if .Retrying}}, retrying {{.Retrying}}/{{.Retries}} ({{.Pending}}){{end}}</dd>
<dt>Last result</dt><dd>{{.Message}}</dd>
<dt>Last run</dt><dd>{{ago .LastRun}}, {{.TookMS}} ms</dd>
<dt>Check</dt><dd>{{.ID}} &middot; every {{dur .Interval}}, timeout {{dur .Timeout}}, {{.Retries}} retries</dd>
<dt>Public page</dt><dd>{{template "vis" .}}</dd>
<dt>Notified</dt><dd>{{.Notified}} {{if not .NotifiedAt.IsZero}}at {{ts .NotifiedAt}}{{end}}</dd>
<dt>30 days</dt><dd>{{template "strip" .Days}}</dd>
</dl></div>{{end}}
<h2>History</h2><div class="card"><table><tr><th>UTC</th><th>status</th><th>ms</th><th>message</th></tr>
{{range .History}}<tr><td>{{ts .Time}}</td><td><span class="dot {{.Status}}"></span> {{.Status}}</td><td>{{.TookMS}}</td><td class="m">{{.Message}}</td></tr>{{end}}
</table></div>
{{template "foot" .}}{{end}}
`))
