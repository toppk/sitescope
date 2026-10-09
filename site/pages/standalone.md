---
title: Without NixOS
eyebrow: Use
lede: One static binary and one systemd user unit. A hub on Fedora or another distribution, watching its own host in-process plus the devices around it.
description: Run a sitescope hub as an ordinary user on a distribution other than NixOS, with the local host collected in-process.
---

The NixOS module is the main way to deploy sitescope, but the binary is
static and needs nothing from the distribution. This page sets up a hub as
an ordinary user's systemd unit. It watches its own host without a separate
agent process, plus devices on the network.

## The binary

```sh
nix build github:toppk/sitescope/<commit>
./result/bin/sitescope version     # X.Y.Z+<short commit>
```

Copy `result/bin/sitescope` somewhere that doesn't change underneath the
running unit, e.g. one directory per release with a `current` symlink.

## The local host

A host entry with `local: true` is collected by the hub itself, in-process,
instead of polled over HTTP. It needs no agent, port or token. The checks
are the same as for a polled host, with the same ids, so the host can move
to a separate agent later by replacing `local: true` with a `url`.

- The `agent` section's command paths apply. The host's own `postfix`,
  `knot` and `wireguard` switches decide what is collected.
- Each collector has a hard timeout, and collection runs off the
  scheduler. A hung command or mount makes that one section report an
  error, and the rest of the report still arrives.
- Without CAP_NET_ADMIN there are no WireGuard stats, so set
  `wireguard: false`.
- System units are read from the system manager. `user: true` units are
  read from the hub user's own manager.

## Configuration

```json
{
  "hub": {
    "listen": "127.0.0.1:8470",
    "stateDir": "/home/me/sitescope/state",
    "controlSocket": "/run/user/1000/sitescope/control.sock",
    "publicURL": "https://status.home.example",
    "lockedAfter": "-1s"
  },
  "alerts": {"enabled": true, "from": "sitescope@home.example", "to": ["me@home.example"],
             "smtp": "127.0.0.1:25", "ntfy": {"enabled": true}},
  "hosts": {"hosts": [{
    "name": "server", "local": true, "os": "fedora", "wireguard": false, "skip": ["swap"],
    "disks": {"/data": {"free": {"warn": 500, "crit": 100}}},
    "units": [{"name": "backup.timer", "user": true, "maxAge": "26h"},
              {"name": "fwupd-refresh.timer", "severity": "warn"}]
  }]},
  "dns": null,
  "ping": {"targets": [{"name": "printer.lan"}, {"name": "frame.lan", "seenWithin": "6h"}]},
  "tcp": {"targets": [{"name": "camera.lan", "port": 554}]},
  "ipp": {"targets": [{"name": "printer", "url": "ipp://printer.lan/ipp/print"}]}
}
```

- `controlSocket` names a path under the user's runtime directory, which
  the unit's `RuntimeDirectory=sitescope` creates. Then `sitescope status`
  and `unlock` work for that user with no group setup. Pass the same
  config with `-config`, or set `SITESCOPE_CONFIG`.
- **The vault.** Checks without a secret run while the vault is locked. If
  the hub has none, keep only the admin login in the vault
  (`sitescope vault set-password`). Set `lockedAfter` negative, so a
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
ExecStart=%h/sitescope/current/sitescope hub -config %h/sitescope/etc/config.json
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
