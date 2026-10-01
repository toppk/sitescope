---
title: NixOS module
eyebrow: Use
lede: nixosModules.default runs the hub, the agent, or both on one host, as separate users with hardened systemd units.
description: Options and generated systemd units of the sitescope NixOS module.
---

## Options

All under `services.sitescope`.

| option | default | |
|---|---|---|
| `enable` | `false` | |
| `role` | | `"hub"` or `"agent"` |
| `listenAddress` | `"127.0.0.1"` for the hub | an agent's `wg0` address; required for an agent |
| `port` | 8470 for the hub, 9105 for an agent | |
| `agent.enable` | `false` | also run an agent on the hub host |
| `agent.listenAddress` | | the hub host's `wg0` address |
| `agent.port` | 9105 | |
| `adminGroup` | `"sitescope-admin"` | members may use the control socket |
| `settings` | `{ }` | the JSON configuration; see [Configuration](configuration.html) |
| `environmentFile` | `null` | `KEY=value` file outside the store |
| `package` | this flake's package | |

The module asserts that an agent has an address, and that `agent.enable`
is only used with `role = "hub"`.

## The hub unit

`sitescope.service`, user `sitescope`:

- State in `/var/lib/sitescope` (mode 0700): `history.db` and `vault.age`.
- Control socket `/run/sitescope/control.sock`, mode 0660, group
  `adminGroup`.
- `MemoryMax=64M`, `GOMEMLIMIT=40MiB`, `LimitMEMLOCK=1M` for the vault
  buffers, `LimitCORE=0`.
- No capabilities. Address families `AF_INET`, `AF_INET6`, `AF_UNIX`.
- `sitescope` in `environment.systemPackages`, and the config at
  `/etc/sitescope/config.json`, for operators.

## The agent unit

`sitescope-agent.service`, user `sitescope-agent`:

- `CAP_NET_ADMIN` as its only capability, ambient, because `wg show`
  needs it.
- Supplementary group `postdrop` when postfix is enabled (for
  `postqueue -j`) and `knot` when Knot is (for its control socket).
- Binds with `IP_FREEBIND`, so it can start before `wg0` is up.
- `MemoryMax=32M`, `GOMEMLIMIT=20MiB`. Adds `AF_NETLINK`.

On a hub host with `agent.enable`, the agent is a separate process and
user, so the process holding the vault never has `CAP_NET_ADMIN`.

## Shared hardening

Both units: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `NoNewPrivileges`, the kernel and cgroup protections,
`RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
`LockPersonality`, `MemoryDenyWriteExecute`,
`SystemCallArchitectures=native`, `UMask=0077`, `Restart=on-failure`.
A config change restarts the unit.

## Firewall

The module doesn't open ports. Open 9105 on `wg0` only:

```nix
networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9105 ];
```

The hub's port stays on loopback, behind your reverse proxy.
