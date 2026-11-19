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
| `settings` | `{ }` | the config, written in Nix; see below |
| `environmentFile` | `null` | `KEY=value` file outside the store |
| `package` | this flake's package | |

The module asserts that an agent has an address, and that `agent.enable`
is only used with `role = "hub"`.

## Using sitescope on NixOS

`settings` takes the same keys as `config.toml`, written in Nix: a TOML
table becomes an attribute set, and `[[host]]` entries become a list.
The [Configuration](configuration.html) example, as settings:

```nix
services.sitescope.settings = {
  hub.publicURL = "https://status.example.org";
  alerts = {
    enabled = true;
    from = "sitescope@example.org";
    to = [ "ops@example.org" ];
    digestTime = "08:00";
  };
  host = [
    { name = "alpha"; url = "http://10.0.0.1:9105"; knot = true; }
    { name = "bravo"; url = "http://10.0.0.2:9105"; postfix = true; }
  ];
  dns = { zones = [ "example.org" ]; primary = "10.0.0.1"; };
  tls.targets = [ { name = "www.example.org"; } ];
  http.targets = [ { name = "www"; url = "https://www.example.org/healthz"; } ];
};
```

The module then:

- fills in `hub.listen`, `hub.stateDir`, `hub.vault`, `hub.controlSocket`,
  `hub.controlGroup`, `hub.hostname` and the whole `agent` section;
- renders the result to JSON in the store, and runs the units with it;
  on the hub host it is also `/etc/sitescope/config.json`, which the CLI
  reads;
- runs `sitescope config -check` on that file when the system builds. An
  unknown, misspelled or renamed key fails `nixos-rebuild` with the key's
  path, before anything deploys. The check reads only the rendered file
  and needs no secrets.

`sitescope config` on the hub host prints what the hub runs with, as
TOML, every default filled in.

### Generated from an inventory

Settings are plain Nix, so they can be derived from what the flake
already knows instead of repeated. For example, with an inventory
attribute set of hosts and a directory of zone files:

```nix
{ lib, inventory, zonesDir }:
let
  zones = map (lib.removeSuffix ".zone")
    (lib.filter (lib.hasSuffix ".zone") (lib.attrNames (builtins.readDir zonesDir)));
  relays = lib.filterAttrs (_: h: h.role == "secondary") inventory;
  addrs = h: [ h.ipv4 h.ipv6 ];
in
{
  public = [
    { name = "DNS"; areas = [ "dns" ]; }
    { name = "Mail"; areas = [ "mail" ]; }
    { name = "Web"; areas = [ "http" "tls" ]; }
  ];
  host = lib.mapAttrsToList (name: h: {
    inherit name;
    url = "http://${h.wg}:9105";
    postfix = h.role == "secondary";
    knot = true;
  }) inventory;
  hosts.wgPeers = lib.mapAttrs' (n: h: lib.nameValuePair h.wgPublicKey n) inventory;
  dns = {
    inherit zones;
    primary = "10.0.0.1";
    servers = lib.mapAttrsToList (name: h: { inherit name; addrs = addrs h; }) relays;
    delegation = lib.mapAttrsToList (_: h: h.publicName) relays;
    resolve = lib.mapAttrs' (_: h: lib.nameValuePair h.publicName (addrs h)) relays;
  };
  domains.names = zones;
  tls.targets = lib.concatMap
    (h: [ { name = h.publicName; } { name = h.publicName; starttls = "smtp"; } ])
    (lib.attrValues relays);
  mail = {
    banner.servers = lib.mapAttrsToList (name: h: { inherit name; addrs = addrs h; expect = h.publicName; }) relays;
    openRelay.servers = lib.mapAttrsToList (name: h: { inherit name; addrs = [ h.ipv4 ]; }) relays;
    blocklists = {
      ips = lib.concatMap addrs (lib.attrValues relays);
      lists = [
        { zone = "zen.spamhaus.org"; ipv6 = true; crit = true; }
        { zone = "bl.spamcop.net"; }
      ];
    };
  };
}
```

Import it as `settings = import ./sitescope-settings.nix { inherit lib inventory; zonesDir = ./zones; };`.

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
