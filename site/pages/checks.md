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
port 25. With `alpn: "h2"` the handshake offers h2 and http/1.1, and the
check warns unless the server chooses h2.

## Certificate Transparency

Section `ct`, once a day per domain. Every public certificate is logged in
Certificate Transparency logs, so a certificate you didn't ask for (a
mis-issuing CA, or someone who briefly controlled your DNS or a web
server) shows up there. `ct.DOMAIN` asks
[Cert Spotter](https://sslmate.com/certspotter/) for the domain's
currently valid certificates, subdomains included:

- an issuer not in `issuers` (default Let's Encrypt) plus that domain's
  `domainIssuers` is **crit**;
- with `names` set, a certificate for any other name is **warn**;
- certificates issued in the last `recent` (7 days) are listed, so a
  renewal you didn't expect is visible.

Acknowledge a certificate by adding its SHA-256 (or a prefix) to `ignore`.
Domains default to `domains.names`; one request per domain covers all its
subdomains. Without a key Cert Spotter allows 10 requests an hour, so the
domains are spread evenly over the day (9 domains run 2h40m apart), a
restart keeps that spacing, and a refused request is retried when Cert
Spotter's `Retry-After` says.
A key in the vault as `certspotter_token` raises the limit; it is used
once the vault is unlocked, and the checks run without it until then.

```nix
ct = {
  # Cloudflare's Universal SSL uses these CAs for proxied names
  domainIssuers."bllue.org" = [ "SSL.com" "Google Trust Services" ];
  # optional; "\\*" is a literal wildcard certificate name, "*" a glob
  names = [ "da.bllue.org" "ne.bllue.org" "status.bllue.org" "zircon.chooser.us" "bllue.org" "\\*.bllue.org" ];
};
```

## HTTP

Section `http`, every minute. `http.NAME` fetches the URL without
following redirects. Crit on a connection error or a status other than
`expectStatus` (200); warn or crit when latency passes `{2, 5}` seconds.

For devices and private services, a target can also set:

- `ca`: a PEM file holding the only CA trusted for this URL. A device's
  self-signed certificate works as its own CA. The name in the URL must
  still match the certificate. Verification is never turned off.
- `body`: text the response must contain, read from the first MiB.
- `redirect`: where the response must redirect to, relative to the URL or
  absolute. Any 3xx status then passes unless `expectStatus` is set.

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
| `host.HOST.memory` | memory in use: total minus `MemAvailable`, so reclaimable page cache doesn't count. The message shows the cache and the three largest services | `{90, 97}` % |
| `host.HOST.pressure` | what a memory shortage costs: share of time tasks stalled waiting for memory (PSI), swap-in pages/s, and OOM kills (any is crit) | stall `{10, 30}` %, swap-in `{100, 1000}`/s |
| `host.HOST.cpu` | CPU busy (not idle or iowait), with iowait, steal and CPU pressure in the message | `{85, 95}` % |
| `host.HOST.diskio` | each disk's busy time, read and write throughput, and the share of time tasks stalled on I/O | busy `{80, 95}` %, stall `{25, 50}` % |
| `host.HOST.network` | per interface throughput; errors and drops per second | errors `{1, 10}`/s, `netMbps` off |
| `host.HOST.cgroups` | each service with a MemoryMax: memory in use as a share of it | `{85, 95}` % |
| `host.HOST.swap` | swap in use | `{60, 90}` % |
| `host.HOST.load` | 5-minute load per CPU | `{2, 4}` |
| `host.HOST.units` | failed systemd units: any is warn | |
| `host.HOST.unit.NAME` | one per entry in the host's `units`: see below | crit, or the unit's `severity` |
| `host.HOST.wireguard` | age of each peer's latest handshake, named through `wgPeers`; not on a host with `wireguard: false` | `{600, 3600}` s |

CPU, memory pressure, disk I/O and network are rates over `rateWindow`
(5 minutes) from the agent's counters, so a brief spike doesn't alert but
a sustained one does. For the first two minutes after the hub or the host
starts they report "collecting a baseline".

### Units and timers

A host's `units` names systemd units that must be up, beyond "no failed
units". Each entry is `{name, user, severity, maxAge}`. `name` includes
the suffix. `user: true` asks the agent user's own systemd manager, for an
agent that runs as a user unit. `severity` is `crit` (the default) or
`warn`.

- A service, socket, mount or other unit must be loaded and `active`.
- A timer must be loaded, `active` and scheduled. The service it starts
  must have succeeded on its last run. A timer whose next run is over an
  hour late is overdue. With `maxAge`, the last run must also be that
  recent.

```json
"units": [
  {"name": "sshd.service"},
  {"name": "backup.timer", "user": true, "maxAge": "26h"},
  {"name": "fwupd-refresh.timer", "severity": "warn"}
]
```

The hub sends the list with each poll, so units are configured only in
the hub's config. An agent older than 1.4.0 ignores the list, and these
checks report unknown until it is upgraded.

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

Both are for NixOS hosts only. A host with another `os` in its entry gets
these instead:

- `host.HOST.reboot`: warn when a newer kernel is installed than the one
  running. Installed kernels are the directories in `/usr/lib/modules`
  that hold a `vmlinuz`, compared the way rpm compares versions.
- `host.HOST.updates`: days since the package database last changed, which
  is the last install, update or removal (rpm, dpkg, apk or pacman):
  `updatesAge`, warn at 30 days, crit at 90.

## Monitoring

`hub.vault`, every tick: `locked` while the vault has been locked under
`hub.lockedAfter` (15 minutes), then warn until someone runs
`sitescope unlock`, so a restart nobody followed up on sends an email.
Negative `lockedAfter` removes the check.

## Cloud

Hourly (token expiry daily), and only while the vault is unlocked; until then these checks
report `locked`.

| id | checks |
|---|---|
| `linode.account` | balance and accrued charges (`uninvoiced` threshold in USD). An unpaid balance is warn; a `payment_due` or abuse-ticket notification is crit |
| `linode.transfer` | network transfer used, `{80, 95}` % of the pool; any billable overage is warn |
| `linode.maintenance` | scheduled maintenance and account notices: warn |
| `linode.events` | in the last `eventWindow` (24h): failed events, and reboots, migrations, rebuilds, resizes, shutdowns, deletions, user and password changes: warn |
| `linode.instance.NAME` | instance status is `running`, else crit |
| `cloudflare.tokens` | daily: sitescope's own token, plus the tokens named in `tokens` (default every active one), by days until they expire (`tokenDays` `{30, 7}`). Disabled, expired or a named token not found is crit; a name it can't see because listing was refused is warn |
| `cloudflare.records.ZONE` | every `expected` record exists: missing is crit. Any other record with an expected name and type, or a `watch`ed one, is warn |
