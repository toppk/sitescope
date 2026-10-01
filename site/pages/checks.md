---
title: Checks
eyebrow: Use
lede: Every check sitescope runs, what it looks at, the id it reports under, and what makes it warn or go critical.
description: The DNS, domain, TLS, HTTP, mail, host, hygiene and cloud checks sitescope runs, with their ids and thresholds.
---

Ids below use `ZONE`, `HOST`, `NAME`, `FAM` (`v4` or `v6`) and `PORT` as
placeholders. Thresholds are `{warn, crit}` and can be changed in
[Configuration](configuration.html).

## DNS

Section `dns`, every 5 minutes (delegation every hour).

| id | checks | warn | crit |
|---|---|---|---|
| `dns.primary` | the hidden primary answers SOA for every zone | | any zone missing |
| `dns.soa.ZONE.HOST.FAM` | each secondary answers SOA with the `aa` flag, over IPv4 and IPv6 | serial differs from the primary's | no answer, error rcode, not authoritative |
| `dns.delegation.ZONE` | the TLD's servers delegate to the expected name servers | extra name servers | missing name servers, no delegation |
| `dns.resolve.NAME` | a public resolver (`1.1.1.1`) returns exactly the expected A and AAAA | | anything else |
| `host.HOST.knot` | from the agent: every zone loaded, secondaries not near expiry | expiry under 14 days | under 3 days, zone missing |

The delegation check asks the parent zone's own servers, not a resolver,
so it sees a registrar change before caches do.

## Domains

Section `domains`, every 12 hours. `domain.NAME` reads the registration
expiry over RDAP: warn under 45 days, crit under 14, crit when expired or
not registered. Servers come from the IANA bootstrap file; `.us` and `.co`,
which aren't in it, have built-in fallbacks, and `domains.servers` can add
more.

## TLS

Section `tls`, every 6 hours. `tls.NAME.PROTO.PORT.FAM` connects over each
IP family, verifies the chain against the system roots and the hostname,
and reports days until the leaf expires: warn under 20, crit under 7.
`starttls: "smtp"` checks a mail server's certificate after `STARTTLS` on
port 25.

## HTTP

Section `http`, every minute. `http.NAME` fetches the URL without
following redirects. Crit on a connection error or a status other than
`expectStatus` (200); warn or crit when latency passes `{2, 5}` seconds.

## Mail

| id | interval | checks |
|---|---|---|
| `mail.banner.HOST.FAM` | 5m | SMTP greeting arrives, mentions `expect`, within `{3, 10}` s |
| `mail.openrelay.HOST.FAM` | 24h | from outside, `RCPT TO` an outside address is refused with `expect` (554). Accepted is crit. The conversation ends at `RCPT`; no message is ever sent |
| `mail.blocklist.IP` | 1h | each IP against each DNS blocklist, through the local resolver. Listed is warn, or crit for lists marked `crit` |
| `host.HOST.postfix` | agent | queue size `{20, 200}` and oldest message `{1h, 4h}` |

Blocklist answers in `127.255.255.0/24` mean the list refused the query,
usually because it came through a public resolver; they are not counted as
listed.

## Hosts

Section `hosts`, every minute. `host.HOST.agent` fetches the agent's
report: crit if it can't. Every other host check reads that report, so it
depends on the agent check and doesn't retry by itself. A section the
agent couldn't collect is warn; a report older than three intervals is
unknown.

| id | checks | default |
|---|---|---|
| `host.HOST.disk` | used space and inodes, worst real filesystem | `{80, 90}` % |
| `host.HOST.memory` | memory in use (total minus available) | `{90, 97}` % |
| `host.HOST.swap` | swap in use | `{60, 90}` % |
| `host.HOST.load` | 5-minute load per CPU | `{2, 4}` |
| `host.HOST.units` | failed systemd units: any is warn | |
| `host.HOST.wireguard` | age of each peer's latest handshake, named through `wgPeers` | `{600, 3600}` s |

A WireGuard peer that only carries occasional traffic may go minutes
without a handshake. Set `PersistentKeepalive` on it, raise the
threshold, or list it in the host's `wgIgnore`.

## Hygiene

From the agent's report, area `hygiene`.

- `host.HOST.reboot`: warn when the kernel, initrd or kernel modules of
  the current system differ from the booted one. A deploy that changes
  only userland doesn't trigger it.
- `host.HOST.nixpkgs`: age of the nixpkgs revision in `nixos-version`:
  warn at 30 days, crit at 90.

## Cloud

Hourly, and only while the vault is unlocked; until then these checks
report `locked`.

| id | checks |
|---|---|
| `linode.account` | balance and accrued charges (`uninvoiced` threshold in USD). An unpaid balance is warn; a `payment_due` or abuse-ticket notification is crit |
| `linode.transfer` | network transfer used, `{80, 95}` % of the pool; any billable overage is warn |
| `linode.maintenance` | scheduled maintenance and account notices: warn |
| `linode.events` | in the last `eventWindow` (24h): failed events, and reboots, migrations, rebuilds, resizes, shutdowns, deletions, user and password changes: warn |
| `linode.instance.NAME` | instance status is `running`, else crit |
| `cloudflare.records.ZONE` | every `expected` record exists: missing is crit. Any other record with an expected name and type, or a `watch`ed one, is warn |
