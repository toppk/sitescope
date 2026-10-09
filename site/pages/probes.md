---
title: Probes and alert volume
eyebrow: Use
lede: What sitescope sends to whom, how often, and how many emails that can turn into. Read this before you point fail2ban, rate limits or an IDS at your own hosts.
description: The network contacts sitescope's hub makes, their rates, how retries change them, and how notifications are paced.
---

## Ask the hub

`sitescope probes` reads the configuration and lists every destination
the hub contacts, what it sends there and how often, when everything is
healthy:

```text
$ sitescope probes
192.0.2.10 25/tcp  12/h
    12/h      connect, read banner, QUIT (1 check every 5m)
    1/day     EHLO, MAIL FROM, RCPT TO an outside address (expects 554), QUIT (1 check every 24h)
192.0.2.10 53/udp  96/h
    96/h      SOA query (8 checks every 5m)
mx.example.org (IPv4) 25/tcp  4/day
    4/day     EHLO, STARTTLS, handshake, QUIT (1 check every 6h)
…
36 destinations, 1305/h in all when healthy.
```

Each check's page in the detail view lists its own contacts too.

## Default rates

Per target, with the default intervals:

| check | contacts | interval | per day |
|---|---|---|---|
| agent poll (`host.*.agent`) | HTTP GET to the agent on wg0 | 1m | 1440 |
| host checks (disk, memory, …) | none: they read the agent's report | | 0 |
| SOA (`dns.soa.*`) | one SOA query per zone, per address | 5m | 288 per zone |
| primary (`dns.primary`) | one SOA query per zone to the primary; the serial is shared by every secondary check for a minute | 5m | 288 per zone |
| delegation | recursive lookups on the public resolver, then one NS query to a parent server | 1h | 24 per zone |
| resolution | A and AAAA on the public resolver | 5m | 576 per name |
| domain expiry | one HTTPS GET to the registry's RDAP server; the IANA bootstrap file once a day | 12h | 2 per domain |
| certificates | one TLS handshake, or EHLO and STARTTLS on SMTP | 6h | 4 per name and family |
| CT logs | one HTTPS GET to api.certspotter.com per domain, domains spread evenly over the day | 24h | 1 per domain |
| HTTP | one GET, redirects not followed | 1m | 1440 per URL |
| SMTP banner | connect, read the 220 line, QUIT | 5m | 288 per address |
| open relay | EHLO, MAIL FROM, RCPT TO an outside address, QUIT | 24h | 1 per address |
| blocklists | one query per list to the local resolver | 1h | 24 per list and address |
| Linode | HTTPS GETs to api.linode.com | 1h | 24 per check |
| Cloudflare | HTTPS GET of the zone's records | 1h | 24 |
| Cloudflare tokens | verify sitescope's token, list API tokens | 24h | 2 to 4 |

Every interval can be changed per section; see
[Configuration](configuration.html). Each check runs at a fixed phase
within its interval (see [scheduling](concepts.html#scheduling)), so
targets see an even rate rather than bursts, and restarting the hub
doesn't repeat the hourly and daily probes.

## When something fails

A check that fails reruns up to `retries` (2) more times,
`retryInterval` (1m) apart, before it alerts. After that it goes back to
its normal interval, so a failing target sees at most three contacts in
three minutes, then the usual rate. A down agent's host checks don't rerun on
their own; they wait for the next poll.

## What servers will log

- **SMTP banner.** A connection that reads the greeting and sends QUIT.
  Postfix logs `connect` and `disconnect ... quit=1 commands=1`.
- **Open relay probe.** `NOQUEUE: reject: RCPT ... 554 5.7.1 ... Relay
  access denied`, once a day per address, then QUIT. This is the line
  fail2ban's postfix filters look for.
- **STARTTLS.** EHLO with the hub's hostname, STARTTLS, a handshake, QUIT.
- **DNS.** Plain SOA queries without recursion; Knot's response rate
  limiting won't notice 8 queries a round.
- **HTTP.** `User-Agent: sitescope/1`.

::: tip
Whitelist the hub's public addresses (IPv4 and IPv6) in fail2ban on every
mail server it probes, for example `ignoreip` in `jail.local`. A daily
relay rejection won't reach a typical `maxretry`, but retries after a
failure add two more within a minute, and a recidive jail remembers.
:::

## Alert volume

The rules that keep email down, with their defaults:

| rule | effect |
|---|---|
| retries | a failure must repeat 3 times (about a minute) before it counts |
| batching | changes from one batch of checks go out as one email |
| one email per change | a check that stays broken sends nothing more |
| `renotifyInterval` (1h) | after an email about a check, its next change waits at least an hour, so flapping sends at most one email an hour per check |
| flap absorption | a check that changes and changes back before its next email is due sends nothing |
| first sighting | a check seen healthy for the first time sends nothing |
| unknown | silent at first; one UNKNOWN email after `unknownAfter` (1h); nothing for checks under a down agent |
| ntfy | only changes to `alerts.ntfy.min` (crit) or worse, and their recoveries; the same batching and renotify rules |
| digest | one a day after `digestTime`; skipped on the day of a start after that time |
| startup | one "vault LOCKED" email per start; one `hub.vault` WARN if still locked after `hub.lockedAfter` (15m), and its recovery |

So the worst case for one check that flaps all day is about 24 emails,
batched with anything else that changed at the same time. A host that goes
down sends one email (its agent check), not one per host check.
