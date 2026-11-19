---
title: Without NixOS
eyebrow: Use
lede: One static binary and one systemd user unit. A hub on Fedora or another distribution, watching its own host in-process plus the devices around it; or a hub on FreeBSD or OpenBSD.
description: Run a sitescope hub as an ordinary user on a distribution other than NixOS, with the local host collected in-process.
---

The NixOS module is the main way to deploy sitescope, but the binary is
static and needs nothing from the distribution. This page sets up a hub as
an ordinary user's systemd unit. It watches its own host without a separate
agent process, plus devices on the network.

## The binary

Starting with 1.6.0, [releases](https://github.com/toppk/sitescope/releases)
include static binaries; earlier releases are tags only. Download the
tarball for your system (`linux-amd64` or `linux-arm64`; from 1.7.0 also
`freebsd-amd64` and `openbsd-amd64`) and check it against the release's
`SHA256SUMS`:

```sh
v=1.6.0
curl -fLO https://github.com/toppk/sitescope/releases/download/v$v/sitescope-$v-linux-amd64.tar.gz
curl -fLO https://github.com/toppk/sitescope/releases/download/v$v/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf sitescope-$v-linux-amd64.tar.gz
./sitescope-$v-linux-amd64/sitescope version     # 1.6.0+<short commit>
```

Or build it: `nix build github:toppk/sitescope/v1.6.0`, then use
`result/bin/sitescope`.

Copy the binary somewhere that doesn't change underneath the
running unit, e.g. one directory per release with a `current` symlink.

## The local host

A `[[host]]` with `local = true` is collected by the hub itself, in-process,
instead of polled over HTTP. It needs no agent, port or token. The checks
are the same as for a polled host, with the same ids, so the host can move
to a separate agent later by replacing `local = true` with a `url`.

- The `agent` section's command paths apply. The host's own `postfix`,
  `knot` and `wireguard` switches decide what is collected.
- Each collector has a hard timeout, and collection runs off the
  scheduler. A hung command or mount makes that one section report an
  error, and the rest of the report still arrives.
- Without CAP_NET_ADMIN there are no WireGuard stats, so set
  `wireguard = false`.
- System units are read from the system manager. `user = true` units are
  read from the hub user's own manager.

## Configuration

`~/sitescope/etc/config.toml`:

<!-- formats: toml json -->
```toml
[hub]
listen = "127.0.0.1:8470"
stateDir = "/home/me/sitescope/state"
controlSocket = "/run/user/1000/sitescope/control.sock"
publicURL = "https://status.home.example"
lockedAfter = "off"

[alerts]
enabled = true
from = "sitescope@home.example"
to = ["me@home.example"]
smtp = "127.0.0.1:25"
ntfy = { enabled = true }

[[host]]
name = "server"
local = true
os = "fedora"
wireguard = false
skip = ["swap"]
disks."/data" = { free = { warn = 500, crit = 100 } }
units = [
  { name = "backup.timer", user = true, maxAge = "26h" },
  { name = "fwupd-refresh.timer", severity = "warn" },
]

[ping]
targets = [
  { name = "printer.lan" },
  { name = "frame.lan", seenWithin = "6h" },
]

[tcp]
targets = [{ name = "camera.lan", port = 554 }]

[ipp]
targets = [{ name = "printer", url = "ipp://printer.lan/ipp/print" }]
```

Check it before starting the unit:
`sitescope config -config ~/sitescope/etc/config.toml -check`.

- `controlSocket` names a path under the user's runtime directory, which
  the unit's `RuntimeDirectory=sitescope` creates. Then `sitescope status`
  and `unlock` work for that user with no group setup. Pass the same
  config with `-config`, or set `SITESCOPE_CONFIG=~/sitescope/etc/config.toml`.
- **The vault.** Checks without a secret run while the vault is locked. If
  the hub has none, keep only the admin login in the vault
  (`sitescope vault set-password`). Set `lockedAfter` to `"off"`, so a
  vault that stays locked after a reboot neither warns nor shows a banner
  on the page, and the hub sends no "unlock" email when it starts. A
  secret the hub needs in order to monitor or alert, like
  `SITESCOPE_NTFY_URL`, goes in the environment file instead.
- **Ping** needs the user's group within `net.ipv4.ping_group_range`.
  Fedora allows every group.

## The unit

```ini
# ~/.config/systemd/user/sitescope.service
[Unit]
Description=sitescope hub

[Service]
ExecStart=%h/sitescope/current/sitescope hub -config %h/sitescope/etc/config.toml
EnvironmentFile=%h/sitescope/etc/env
RuntimeDirectory=sitescope
Restart=on-failure
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

The environment file is mode 0600 and holds `SITESCOPE_HEARTBEAT_URL` and
`SITESCOPE_NTFY_URL`. Run `loginctl enable-linger` for the user, so the
unit starts at boot without a login. Then:

```sh
systemctl --user enable --now sitescope
sitescope verify -url http://127.0.0.1:8470 -version X.Y.Z+<short commit>
```

Put a reverse proxy with TLS in front of `listen` to serve the page beyond
loopback.

## On FreeBSD and OpenBSD

From 1.7.0 the hub and the CLI run on FreeBSD and OpenBSD (x86-64): the
vault, the control socket, the status page and every check that works over
the network. Tested on FreeBSD 15.1 and OpenBSD 8.0.

- **No agent, and no local host.** The agent's collectors read Linux's
  `/proc`, `/sys` and systemd, so `sitescope agent` refuses to start, and a
  hub with a `local = true` host refuses to start. Watch Linux hosts through
  their agents (`url`), as usual.
- **Ping needs root.** Neither system has Linux's unprivileged ping socket,
  so ICMP needs a raw socket. Run as an ordinary user, a ping check fails
  and says so. TCP, HTTP and IPP device checks need no privilege.
- **Locked memory.** The vault's buffers are `mlock`ed, like
  `LimitMEMLOCK=1M` on Linux. FreeBSD's default login class allows 64 KiB:
  raise `memorylocked` to `1M` in `/etc/login.conf` and run `cap_mkdb`.
  OpenBSD's default is ample.
- **The service.** There's no systemd unit, so run
  `sitescope hub -config /path/config.toml` under the system's own service
  manager: an `rc.d` script, or `daemon(8)` on FreeBSD.
