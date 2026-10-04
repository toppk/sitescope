---
title: Overview
hero: true
hero-image: assets/logo-512.webp
hero-eyebrow: Health monitor · status page · NixOS
hero-title: A few hosts, watched closely.
hero-lede: sitescope is one static Go binary that watches a small fleet from the inside and the outside. Agents report what each host knows about itself, a hub probes what the world sees, and you get an email when something changes and a status page for everyone else.
hero-links:
  - label: Get started
    href: getting-started.html
    kind: primary
  - label: See the checks
    href: checks.html
    kind: secondary
description: sitescope is a small health monitor for a handful of NixOS hosts. Agents report host facts over WireGuard, a hub runs DNS, TLS, CT, HTTP, mail, RDAP and cloud checks, emails state changes and serves a status page.
---

## What sitescope does

It is named after HP SiteScope, and has the same idea at a much smaller
scale: a few servers, a few zones, a mail relay or two, and one person who
needs to know when any of it goes wrong.

::: cards
::: card
[Inside]{.label}

### The agent

Runs on every host and serves one JSON report on its WireGuard address:
disk, memory, swap, load, failed units, whether a reboot is pending, how old
nixpkgs is, WireGuard handshakes, the postfix queue and Knot zone status,
plus CPU, pressure, disk and network counters. The same facts are on
`/metrics` for Prometheus.
:::

::: card
[Outside]{.label}

### The hub

Polls the agents and probes from the outside: DNS serials and delegation,
domain expiry over RDAP, certificate lifetimes and ALPN, Certificate
Transparency logs, HTTP status and latency, SMTP banners, an open-relay
probe, blocklists, Linode billing, Cloudflare record drift and API token
expiry.
:::

::: card
[Out loud]{.label}

### Alerts and status

An email when a check changes state, a daily digest of what isn't healthy,
a dead-man's-switch heartbeat, a public page of traffic lights, and a
detailed view with 30 days of history behind a password.
:::
:::

## What it promises

::: safety
**Read only, everywhere.** sitescope never changes the infrastructure it
watches. Its API tokens are read-only, its probes only ask, and the
open-relay probe ends the conversation before any message is sent.
:::

- **Secrets stay in memory, locked.** API tokens live in an age-encrypted
  vault. The hub starts locked; an operator unlocks it from a shell. The
  decrypted values sit in mlocked memory that is never swapped or dumped,
  and are zeroed on lock.
- **You choose what the public page reveals.** Each check is listed under
  a label, folded into a service light, or kept off the page entirely.
  Messages and error text are never shown.
- **One email per real change.** A failure must repeat before it counts,
  a recovery counts at once, and a flapping check is held back.
- **Small.** The hub ran in about 20 MB with 70 checks; an agent runs in
  about 12 MB. Between scheduled steps the hub sleeps.

## How it fits together

::: stack
::: tier
[agent [host A]{.small}]{.box}
[agent [host B]{.small}]{.box}
[agent [host C]{.small}]{.box}
:::

[GET /v1/report over WireGuard, bearer token]{.wire}

::: tier
[sitescope hub [scheduler · probes · state machine · mailer]{.small}]{.box .daemon}
:::

::: tier
[status page [public lights, detail behind auth]{.small}]{.box .socket}
[control.sock [unlock · lock · status]{.small}]{.box .socket}
:::

::: tier
[history.db [bbolt, 35 days]{.small}]{.box .store}
[vault.age [age, scrypt]{.small}]{.box .store}
:::
:::

The hub runs on one host, behind a reverse proxy on `127.0.0.1:8470`.
Each agent listens on its host's `wg0` address, port 9105. The NixOS
module sets up both, with hardened systemd units.

## A first look

```sh
sitescope check -config config.json            # every check once, no daemon
sitescope check -config config.json -match dns.soa
sitescope unlock                               # on the hub host, after a restart
sitescope status
```
