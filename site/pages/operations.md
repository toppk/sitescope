---
title: Operations
eyebrow: Use
lede: Day to day, sitescope needs one thing from you, an unlock after every restart. This page covers that, the logs, the files, and what to do when a check is wrong.
description: "Running sitescope: unlocking after restarts, logs, state files, backups and troubleshooting."
---

## After every restart

The hub starts locked and emails "sitescope started on HOST - vault
LOCKED, run sitescope unlock". Until you do, the cloud checks show
`locked` and the detail view is unavailable; everything else runs and
alerts as usual. Fifteen minutes later (`hub.lockedAfter`) `hub.vault`
warns by email, in case the first one was missed.

```sh
sitescope unlock
sitescope status      # ok vault unlocked (admin_password_hash, cloudflare_token, linode_token), 71 checks
```

## Logs

Both units log to the journal, one structured line per event. Check
results are not logged; status changes, mail sends, unlocks (with the
caller's uid and pid) and errors are.

```sh
journalctl -u sitescope -f
journalctl -u sitescope-agent -f
```

## Files

| path | what |
|---|---|
| `/var/lib/sitescope/history.db` | bbolt: states and history. About 20 MB at 100 checks for 35 days |
| `/var/lib/sitescope/vault.age` | the vault. Back it up |
| `/run/sitescope/control.sock` | the control socket |
| `/etc/sitescope/config.json` | the configuration, for the CLI |

Deleting `history.db` while the hub is stopped is safe: it starts over,
and every check's first sighting is silent again.

## Memory

| process | measured | limit |
|---|---|---|
| hub | about 19 MB, measured with 70 checks | `GOMEMLIMIT=40MiB`, `MemoryMax=64M` |
| agent | about 12 MB | `GOMEMLIMIT=20MiB`, `MemoryMax=32M` |

Unlock briefly needs another 32 MiB for scrypt; the hub returns it to the
system straight after.

## Troubleshooting

**A host check says "agent unreachable".**
Is `sitescope-agent` running on that host, is 9105 open on its `wg0`, and
is there a WireGuard peer between the hub host and it? Try
`curl -H "Authorization: Bearer $TOKEN" http://ADDR:9105/v1/report` from
the hub host.

**"agent returned 401".**
`SITESCOPE_AGENT_TOKEN` differs between the hub and that agent.

**A WireGuard handshake warns, but the tunnel works.**
Handshakes only happen when there is traffic. Set `PersistentKeepalive` on
quiet peers, raise `hosts.wgHandshake`, or list the peer in the host's
`wgIgnore`.

**"agent could not collect knot" or "postfix".**
The agent needs the `knot` or `postdrop` group, which the module adds when
the service is enabled on that host. Check `knotSocket` if Knot's control
socket isn't at `/run/knot/knot.sock`.

**Blocklists all say "refused".**
The resolver at `mail.blocklists.resolver` is forwarding to a public
resolver. Blocklists need a recursive resolver that asks them directly.

**A domain is unknown with "no RDAP server".**
Its TLD isn't in the IANA bootstrap. Add its registry's RDAP base URL to
`domains.servers`.

**CT checks are unknown with "rate limited".**
Cert Spotter allows 10 unauthenticated requests an hour. The check retries
when Cert Spotter says to; a `certspotter_token` in the vault raises the
limit.

**`cloudflare.tokens` says a token is "not visible".**
Sitescope's Cloudflare token can't list tokens. Give it API Tokens Read
(User, or Account for account-owned tokens).

**Try a check by hand.**

```sh
sitescope check -match dns.soa.example.org
```
