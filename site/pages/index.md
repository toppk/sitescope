---
title: Overview
hero: true
hero-image: assets/logo-512.webp
hero-eyebrow: Health monitor · status page · sealed vault
hero-title: A few hosts, watched closely.
hero-lede: sitescope is one static Go binary that watches a small fleet from the inside and the outside. Agents answer one read-only question about their host, a hub probes what the world sees, its credentials stay sealed in an age vault until you unlock it, and you get an email when something changes and a status page for everyone else.
hero-links:
  - label: Get started
    href: getting-started.html
    kind: primary
  - label: See the checks
    href: checks.html
    kind: secondary
description: sitescope is a small health monitor for a handful of hosts. Read-only agents report host facts over WireGuard; a hub runs DNS, TLS, CT, HTTP, mail, RDAP, device and cloud checks with its credentials in a locked age vault, emails state changes and serves a status page. NixOS module, or static binaries for Linux, FreeBSD and OpenBSD.
---

## What sitescope does

It is named after HP SiteScope, and has the same idea at a much smaller
scale: a few servers, a few zones, a mail relay or two, and one person who
needs to know when any of it goes wrong.

::: cards
::: card
[Inside]{.label}

### The agent

Runs on every Linux host and answers one question, when the hub asks:
what does this host look like? Disk, memory, swap, load, failed units and
the units and timers you name, a pending reboot, package age, WireGuard
handshakes, the postfix queue, Knot zones, and CPU, pressure, disk and
network counters. It takes no commands and never calls out. The same
facts are on `/metrics` for Prometheus.
:::

::: card
[Outside]{.label}

### The hub

Polls the agents and probes from the outside: DNS serials and delegation,
domain expiry over RDAP, certificate lifetimes and ALPN, Certificate
Transparency logs, HTTP status and latency, SMTP banners, an open-relay
probe, blocklists, devices on the LAN (ping, TCP, printers over IPP),
Linode billing, Cloudflare record drift and API token expiry.
:::

::: card
[Out loud]{.label}

### Alerts and status

An email when a check changes state, a push to your phone over ntfy for
what can't wait, a daily digest of what isn't healthy, a dead-man's-switch
heartbeat, a public page of traffic lights, and a detailed view with 30
days of history behind a password.
:::

::: card
[Locked]{.label}

### The vault

The hub's API tokens and the detail view's password hash live in an
age-encrypted vault. The hub starts locked, and the checks that need a
secret wait until an operator unlocks it from a shell on the hub host,
never from the web. Decrypted, they sit in locked memory outside the Go
heap, kept out of swap and core dumps, and are zeroed on lock.
[Vault and secrets](vault.html)
:::
:::

## What it promises

::: safety
**Read only, everywhere.** sitescope never changes the infrastructure it
watches. Its API tokens are read-only, its probes only ask, and the
open-relay probe ends the conversation before any message is sent.
:::

- **Secrets stay in memory, locked.** Plaintext never touches the disk or
  a log line, and other processes of the same user can't read the hub's
  memory, on Linux, FreeBSD and OpenBSD alike.
- **Agents take no orders.** The hub pulls; an agent only answers a
  read-only question, as its own user, on its WireGuard address. There is
  nothing to send it but a list of unit names to look up. See
  [Hub and agent](concepts.html#hub-and-agent).
- **You choose what the public page reveals.** Each check is listed under
  a label, folded into a service light, or kept off the page entirely.
  Messages and error text are never shown.
- **One email per real change.** A failure must repeat before it counts,
  a recovery counts at once, and a flapping check is held back.
- **Small.** The hub runs in about 14 MB with 140 checks (around 40 MB
  briefly while unlocking); an agent in about 12 MB. Between scheduled steps the hub
  sleeps.

## How it fits together

::: stack
::: tier
[agent [host A]{.small}]{.box}
[agent [host B]{.small}]{.box}
[agent [host C]{.small}]{.box}
:::

[the hub asks: GET /v1/report over WireGuard, bearer token; agents never call out]{.wire}

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
module sets up both, with hardened systemd units. Without NixOS, the
static binaries run the hub on Linux, FreeBSD or OpenBSD and the agent on
Linux, from one TOML file; see [Without NixOS](standalone.html).

## A first look

```sh
sitescope check -config config.toml            # every check once, no daemon
sitescope check -config config.toml -match dns.soa
sitescope unlock                               # on the hub host, after a restart
sitescope status
```
