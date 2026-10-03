---
title: Getting started
eyebrow: Start
lede: Add the flake, turn on a hub and its agents, store two tokens in the vault, unlock it. Most of the work is writing down what you expect your hosts to look like.
description: Install sitescope with its NixOS module, deploy a hub and agents, and set up the vault.
---

## Requirements

- **NixOS hosts** joined by WireGuard (`wg0`). The agent binds to the
  host's `wg0` address; the hub reaches every agent over it.
- A **local MTA** on the hub host listening on `127.0.0.1:25` for alert
  mail, and a **local resolver** on `127.0.0.1:53` for blocklist lookups
  (public resolvers are refused by most blocklists).
- A **reverse proxy** for the status page, if it should be public.
- Optional: a Linode and a Cloudflare read-only token, and a heartbeat URL
  (healthchecks.io or similar).

## Add the flake

```nix
inputs.sitescope.url = "github:toppk/sitescope";
inputs.sitescope.inputs.nixpkgs.follows = "nixpkgs";
```

and import `inputs.sitescope.nixosModules.default` on each host.

## Write the environment file

On every host, outside the Nix store and readable only by root:

```sh
# /var/lib/sitescope-secrets/sitescope.env
SITESCOPE_AGENT_TOKEN=<the same long random value on every host>
SITESCOPE_HEARTBEAT_URL=https://hc-ping.com/<uuid>     # hub only
```

`openssl rand -hex 32` makes a good token.

## Turn on the hub

On the host that watches the others (it can watch itself too):

```nix
services.sitescope = {
  enable = true;
  role = "hub";
  agent = { enable = true; listenAddress = "10.0.0.2"; };   # this host's wg0 address
  environmentFile = "/var/lib/sitescope-secrets/sitescope.env";
  settings = import ./sitescope-settings.nix { inherit lib; };
};
users.users.alice.extraGroups = [ "sitescope-admin" ];
networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9105 ];
```

Point the reverse proxy for your status hostname at `127.0.0.1:8470`.

## Turn on the agents

On every other host:

```nix
services.sitescope = {
  enable = true;
  role = "agent";
  listenAddress = "10.0.0.3";    # this host's wg0 address
  environmentFile = "/var/lib/sitescope-secrets/sitescope.env";
};
networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9105 ];
```

The agent turns on its postfix and Knot sections by itself when those
services are enabled on the host.

## Describe what you expect

`settings` is where the hosts, zones, certificates and URLs go. A minimal
start:

```nix
{
  alerts = { enabled = true; from = "sitescope@example.org"; to = [ "ops@example.org" ]; digestTime = "08:00"; };
  hub.publicURL = "https://status.example.org";
  hosts.hosts = [
    { name = "a"; url = "http://10.0.0.1:9105"; knot = true; }
    { name = "b"; url = "http://10.0.0.2:9105"; postfix = true; }
  ];
  dns = { zones = [ "example.org" ]; primary = "10.0.0.1"; };
  tls.targets = [ { name = "www.example.org"; } ];
  http.targets = [ { name = "www"; url = "https://www.example.org/"; } ];
}
```

[Configuration](configuration.html) lists every key, and
[Checks](checks.html) what each section checks. Before deploying, try it:

```sh
nix build github:toppk/sitescope
nix eval --json .#nixosConfigurations.hub.config.services.sitescope.settings > /tmp/sitescope.json
./result/bin/sitescope check -config /tmp/sitescope.json
```

## Set up the vault

After the first deploy, on the hub host:

```sh
sudo -u sitescope sitescope vault set linode_token        # creates the vault, asks for a new passphrase twice
sudo -u sitescope sitescope vault set cloudflare_token
sudo -u sitescope sitescope vault set-password            # password for the detail view (user "admin")
sitescope unlock
```

The hub sends "vault LOCKED" email every time it starts, and the
`hub.vault` check warns if the vault is still locked 15 minutes later. Run
`sitescope unlock` again after each restart. See
[Vault and secrets](vault.html).
