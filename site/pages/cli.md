---
title: Command line
eyebrow: Use
lede: One binary, every role. The daemons, the operator commands that talk to a running hub, the vault editor and a one-shot checker.
description: Every sitescope subcommand and its flags.
---

```text
sitescope <command> [flags]
```

## Daemons

`sitescope hub -config FILE`
:   Polls agents, runs probes, keeps history, sends mail, serves the status
    page and the control socket. Started by `sitescope.service`.

`sitescope agent -config FILE`
:   Serves this host's report on `agent.listen`. Started by
    `sitescope-agent.service`.

## Talking to the hub

These connect to the control socket: `-socket`, or else `hub.controlSocket`
from the hub's config (`-config`, `$SITESCOPE_CONFIG` or
`/etc/sitescope/config.json`). With neither a socket nor a config, they
stop with an error rather than guess. You need to be in the admin group.

`sitescope unlock`
:   Asks for the vault passphrase on the terminal, without echo, and sends
    it to the hub. The hub decrypts the vault into locked memory and runs
    the checks that were waiting for it. Run it again after editing the
    vault.

`sitescope lock`
:   Zeroes the hub's decrypted secrets and its login cache. Credential
    checks go back to `locked`.

`sitescope status`
:   Prints whether the vault is locked, the names of the loaded secrets
    when it isn't, and the number of checks.

## The vault

These read and write the vault file directly: `-vault`, or else `hub.vault`
from the hub's config (found as above); with neither, they stop with an
error. Run them as the hub user:
`sudo -u sitescope sitescope vault …`. Each asks for the passphrase.

`sitescope vault set NAME`
:   Stores a secret. The value comes from stdin, or is prompted for without
    echo. The first `set` creates the vault and asks for a new passphrase
    twice. Names are letters, digits, `_`, `.` and `-`.

`sitescope vault rm NAME`
:   Deletes a secret.

`sitescope vault list`
:   Prints secret names, never values.

`sitescope vault set-password`
:   Asks twice for the detail view's admin password and stores its bcrypt
    hash as `admin_password_hash`.

## One-shot checks

`sitescope check -config FILE [-match SUBSTR]`
:   Runs every check that doesn't need the vault once, in parallel, and
    prints one line per check: status, id, time taken, message. Exits 2 if
    any is crit. Useful for trying a configuration before deploying it.

```text
$ sitescope check -config config.json -match tls
ok    tls.www.example.org.https.443.v4   61ms   certificate expires 2026-12-01 (61 days), issuer E7
ok    tls.www.example.org.https.443.v6   58ms   certificate expires 2026-12-01 (61 days), issuer E7
warn  tls.mx.example.org.smtp.25.v4      212ms  certificate expires 2026-10-15 (14 days), issuer E8
```

## What the hub contacts

`sitescope probes -config FILE`
:   Lists every destination the hub contacts (address or host, port and
    protocol), what it sends there and how often, when all is healthy.
    See [Probes and alert volume](probes.html).

## Checking a running hub

`sitescope verify -url URL [flags]`
:   Reads the hub's `/healthz` and `/status.json` and checks them, for use
    after a deploy. It only sends two GETs, without credentials. Prints one
    line per expectation and exits 1 if any is unmet.

    | flag | expects |
    |---|---|
    | `-version V` | `/status.json`'s version: exactly `X.Y.Z+rev`, or just the release when `V` has no `+rev` |
    | `-vault STATE` | the vault state: `locked` or `unlocked` |
    | `-overall STATUS` | the overall status: `ok`, `warn`, `crit` or `unknown` |
    | `-services N` | the number of services in `/status.json` |
    | `-checks N` | the number of checks listed in `/status.json` (class A only) |
    | `-ca FILE` | trust only this PEM CA for the hub's certificate, for a hub behind a private CA |
    | `-timeout D` | per request; default `10s` |

```text
$ sitescope verify -url https://status.example.org -version 1.4.0+abc1234 -vault unlocked -overall ok
ok    healthz   200 ok
ok    version   1.4.0+abc1234
ok    vault     unlocked
ok    overall   ok
```

## Other

`sitescope version`
:   Prints the version: the release plus the flake's git revision, e.g.
    `1.1.0+5c6dc53` (`VERSION`, then the commit). The page footer and `/status.json` show it too.
