---
title: Concepts
eyebrow: Start
lede: Checks, statuses, retries, notifications and history. How sitescope decides that something changed, and when to tell you.
description: How sitescope's checks, statuses, retries, notifications and history work.
---

## Checks

Configuration is written in sections (`dns`, `tls`, `hosts`, …). The hub
expands each section into flat checks, each with a stable id such as
`dns.soa.example.org.b.v6` or `host.a.disk`. Ids name the same thing
across restarts, so history follows them.

Each check belongs to an **area**: `dns`, `domains`, `tls`, `http`, `mail`,
`hosts`, `hygiene` or `cloud`. Each check also has a **visibility**:
`public` (listed on the public page under a label), `grouped` (folded into
a service light) or `private` (not on the public page at all). See
[Status page and API](web.html#visibility).

Every check has its own timing: `interval`, `timeout`, `retries` and
`retryInterval`, set per section or inherited from `defaults`.

## Scheduling

The hub plans its work instead of polling a clock. Every run lands on a
grid of `hub.tick` steps (1 minute) counted from the hub's start, and
between steps the hub sleeps.

- **Phases.** Each check gets a fixed offset within its interval.
  Checks that run every tick (the agent polls) start together; slower
  checks get a stable spot in the first 15 minutes, so the 5-minute DNS
  and SMTP probes and the hourly ones don't all hit their targets at once.
- **Spread groups.** Checks that share a rate-limited API are spaced evenly
  over their interval: the CT checks, one per domain, every 24 hours.
- **Host checks** run as soon as their agent's report arrives.
- **Restarts.** A check that ran before a restart keeps its pace; one that
  never ran shows "first run at …" until its slot.
- **Retries** wait for the next step after `retryInterval`; an API's
  `Retry-After` brings the next run forward.
- **Housekeeping** follows the work: when a batch of results is in, the
  hub sends one email for what changed, then pings the heartbeat, saves
  state and prunes history when those are due. It wakes at least every
  5 minutes.

## Statuses

| status | means | counts toward a light |
|---|---|---|
| `ok` | healthy | yes |
| `warn` | a threshold's warn bound crossed, or a soft problem | yes |
| `crit` | a crit bound crossed, or the thing is down | yes |
| `unknown` | not run yet, or the check itself couldn't decide | yes, as unknown |
| `locked` | needs a vault secret and the vault is locked | no |

Thresholds are written `{ warn, crit }`. Whether "above" or "below" is bad
depends on the check: disk use is bad above, days to expiry is bad below.
A bound of `0` turns it off.

## Retries

A move **into** `warn` or `crit` must be seen `retries` more times,
`retryInterval` apart, before it is committed. While retrying, the check
keeps its previous status and shows "retrying 1/2". A move to `ok`,
`unknown` or `locked` is committed at once.

Checks derived from an agent's report (`host.a.disk`, `host.a.postfix`, …)
depend on the agent check `host.a.agent` and don't retry themselves: the
report already passed the agent's retries.

## Notifications

When a batch of checks finishes, the hub gathers the committed changes
that are due and sends them in one email.

- **The first ok is silent.** A check seen healthy for the first time
  sends nothing.
- **Renotify interval.** After a check has been notified, its next change
  waits at least `alerts.renotifyInterval` (1 hour by default).
- **Flapping is absorbed.** If a check changes and changes back before its
  next notification is due, nothing is sent.
- **Daily digest.** After `alerts.digestTime`, one email lists every check
  that isn't ok. A hub started after that time skips the day's digest, and
  none goes out in the first 10 minutes after a start, so a restart never
  mails a list of checks that simply haven't run yet.
- **Unknown waits.** A move to `unknown` doesn't send email at once. A
  check still unknown after `alerts.unknownAfter` (1 hour, counted from
  startup for a check that has never produced a result) is reported once
  as UNKNOWN, and its recovery is reported. Checks whose agent is down stay
  quiet; the agent's own alert covers them.
- **Startup.** Every start sends "sitescope started on HOST - vault LOCKED,
  run sitescope unlock".

A failed send is retried on the next 30-second round.

## Heartbeat

Every `hub.heartbeatInterval` (1 minute by default) in which the store had
no errors, the hub GETs `SITESCOPE_HEARTBEAT_URL`. Set the heartbeat
service's period to match, with some grace. If the hub dies, hangs, or loses its disk, the
pings stop and the heartbeat service tells you. That covers the one thing
sitescope can't report on: itself.

## History

The hub keeps history in `/var/lib/sitescope/history.db` (bbolt): every
status change, plus one sample per `hub.sampleEvery` (15 minutes) for each
check. History older than `hub.retentionDays` (35) is pruned every six
hours, and so is history of checks that are no longer configured. Current
states are saved every five minutes and on shutdown, so a restart picks up
where it left off.
