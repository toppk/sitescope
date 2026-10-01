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
:   The overall status and one light per service, the time of the last
    update, and a banner while the vault is locked. Services are groups of
    areas from `public`; by default each area is its own light. Nothing
    else: no hostnames, addresses, check names, versions or messages. The
    page reloads every `hub.refresh` seconds and works without JavaScript.

`/healthz`
:   200 while the scheduler is ticking, 503 if it has stalled. For the
    proxy's health checks.

## Behind authentication

HTTP basic auth, user `admin`, password checked against the bcrypt hash in
the vault. These answer 503 while the vault is locked. Failed logins are
limited to one per second; a successful login is cached for ten minutes,
and the cache is cleared on `lock`.

`/detail`
:   Every check grouped by area, with its status, how long it has had it,
    its last message, and retry progress.

`/detail/check?id=ID`
:   One check: timing, a 30-day strip of daily worst status, and its
    history of changes.

`/api/status`
:   The same as JSON:

```json
{
  "time": "2026-10-01T12:00:00Z",
  "overall": "warn",
  "vaultLocked": false,
  "services": [
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
      "message": "34 queued, oldest 41m"
    }
  ]
}
```

`retrying` appears on a check that is in the middle of its retries.

## Headers

Every response sets `Content-Security-Policy: default-src 'none';
style-src 'unsafe-inline'; frame-ancestors 'none'` (no scripts, no
framing), `X-Content-Type-Options: nosniff` and
`Referrer-Policy: no-referrer`. Authenticated responses are
`Cache-Control: no-store`.
