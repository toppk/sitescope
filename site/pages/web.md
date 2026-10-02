---
title: Status page and API
eyebrow: Use
lede: A public page of traffic lights, and behind a password the detail view and a JSON API. All read only.
description: sitescope's public status page, its authenticated detail view, and the /api/status JSON.
---

The hub serves HTTP on `127.0.0.1:8470`. Put a reverse proxy with TLS in
front of it.

## Public

`/`
:   The overall status with a count of checks by status, then one
    collapsible section per service showing how many of its checks are ok
    (for example "Mail 11/11"). Inside, checks about the same host or
    target are folded into a group of their own ("da2 16/17"). Sections
    with a warning or failure open by themselves. What each check
    contributes depends on its visibility, below. Messages are never shown.

    The page reloads every `hub.refresh` seconds and works without
    JavaScript. With it, the sun button switches light and dark (otherwise
    the system setting applies), and expanded sections stay expanded across
    reloads. It uses the documentation site's palette and fonts; the fonts
    come from Google Fonts, with system fallbacks. The footer links to the
    documentation (`hub.docsURL`).

`/status.json`
:   The public page as JSON, with exactly the same facts: overall status,
    whether the vault is locked, and each service with its class A checks.

    ```json
    {
      "time": "2026-10-01T12:00:00Z",
      "overall": "crit",
      "vaultLocked": false,
      "services": [
        { "name": "Web", "status": "ok", "checks": [ { "name": "Main site", "status": "ok" } ] },
        { "name": "DNS", "status": "ok" }
      ]
    }
    ```

`/healthz`
:   200 while the scheduler is ticking, 503 if it has stalled. For the
    proxy's health checks.

## Visibility

Every check has one of three visibility classes, which decide how much of
it the public page shows:

| class | visibility | on the public page |
|---|---|---|
| A | `public` | its own row, with a label you choose, under its service's light |
| B | `grouped` | folded into its service's light; nothing about the check itself |
| C | `private` | nowhere: no row, no light, and it doesn't count toward the overall status |

The detail view and `/api/status` always show every check, and say which
class each one is in.

Classes come from the rules in `public`. Each check takes the **first**
rule it matches, by area or by check id glob (`*` matches any run of
characters, `?` one). A check that matches no rule is **public**, listed
under its area's light with its own name. So with no rules at all,
everything is class A, and you hide things as you go. To make private the
default instead, end the list with `{ visibility = "private"; checks = [ "*" ]; }`.

```nix
public = [
  # A: listed one by one, with labels that give nothing away
  { name = "Website"; visibility = "public";
    checks = [ "http.www" "http.shop" ];
    labels = { "http.www" = "Main site"; "http.shop" = "Shop"; }; }

  # C: rules for private checks come before the broader rules they'd otherwise match
  { visibility = "private"; checks = [ "dns.primary" "host.*.wireguard" ]; }

  # B: whole areas behind one light each
  { name = "DNS"; areas = [ "dns" ]; }
  { name = "Mail"; areas = [ "mail" ]; }
  { name = "Servers"; areas = [ "hosts" "hygiene" ]; }
  # everything else stays public, under its area's name
];
```

::: warning
A `public` row without a label shows the check's own name, such as
"Certificate mx.example.org (smtp:25, IPv4)". Give every class A check a
label unless its name is already fine to publish.
:::

## Behind authentication

HTTP basic auth, user `admin`, password checked against the bcrypt hash in
the vault. These answer 503 while the vault is locked. Failed logins are
limited to one per second; a successful login is cached for ten minutes,
and the cache is cleared on `lock`.

`/detail`
:   Every check, in the same collapsible areas and groups, with its
    status, how long it has had it, its last message, interval, retry
    progress, visibility and a 30-day strip. The overall status here
    includes private checks.

`/detail/check?id=ID`
:   One check: timing, the network contacts each run makes, a 30-day
    strip of daily worst status, and its history of changes.

`/api/status`
:   The same as JSON:

```json
{
  "time": "2026-10-01T12:00:00Z",
  "overall": "warn",
  "publicOverall": "warn",
  "vaultLocked": false,
  "services": [
    { "name": "Website", "status": "ok", "checks": [ { "name": "Main site", "status": "ok" } ] },
    { "name": "DNS", "status": "ok" },
    { "name": "Mail", "status": "warn" }
  ],
  "checks": [
    {
      "id": "host.b.postfix",
      "name": "b mail queue",
      "area": "mail",
      "status": "warn",
      "since": "2026-10-01T11:42:10Z",
      "lastRun": "2026-10-01T11:59:31Z",
      "tookMs": 0,
      "message": "34 queued, oldest 41m",
      "visibility": "grouped",
      "service": "Mail"
    }
  ]
}
```

`overall` covers every check and `publicOverall` only what the public page
counts. `retrying` appears on a check that is in the middle of its retries;
`publicName` on a class A check.

## Headers

Every response sets a `Content-Security-Policy` that allows only the
hub's own scripts, styles and images (served from `/static/`), Google
Fonts, and no framing or forms, plus `X-Content-Type-Options: nosniff`
and `Referrer-Policy: no-referrer`. Authenticated responses are
`Cache-Control: no-store`.
