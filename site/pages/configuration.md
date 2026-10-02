---
title: Configuration
eyebrow: Use
lede: One JSON file, rendered by the NixOS module from services.sitescope.settings. Every key is optional; nothing about your hosts is built in.
description: Every sitescope configuration key, its default, and the environment variables it reads.
---

## Where it lives

The module writes `services.sitescope.settings` to the Nix store and runs
`sitescope hub -config <that file>`. The hub host also gets a copy at
`/etc/sitescope/config.json`, which the CLI reads by default (or
`$SITESCOPE_CONFIG`, or `-config FILE`).

The module fills in `hub.listen`, `hub.stateDir`, `hub.vault`,
`hub.controlSocket`, `hub.controlGroup`, `hub.hostname` and the whole
`agent` section. You write the rest.

## Durations and thresholds

A duration is a string like `"90s"`, `"5m"`, `"12h"`, or a number of
seconds. A threshold is `{ warn = …; crit = …; }`; `0` turns a bound off.

## Timing

`defaults` sets timing for every check, and every section (and each HTTP
target) can override it with the same four keys:

| key | default | |
|---|---|---|
| `interval` | `"5m"` | time between runs (some sections have their own default, see [Checks](checks.html)) |
| `timeout` | `"10s"` | per run |
| `retries` | `2` | further failures needed before warn or crit is committed |
| `retryInterval` | `"30s"` | time between those retries |

## Reference

| key | default | notes |
|---|---|---|
| `hub` | `title: "Status"`, `publicURL`, `refresh: 60`, `docsURL`, `retentionDays: 35`, `sampleEvery: "15m"`, `heartbeatInterval: "1m"`, `concurrency: 8` | `refresh` is the page's reload interval in seconds; `concurrency` caps checks running at once |
| `alerts` | `enabled: false`, `smtp: "127.0.0.1:25"`, `from`, `to`, `subjectPrefix: "[sitescope]"`, `renotifyInterval: "1h"`, `unknownAfter: "1h"`, `digestTime` | `digestTime` is `"HH:MM"`, local time; unset means no digest |
| `public` | every check public, under its area | ordered rules `[{name, areas, checks, visibility, labels}]`; `visibility` is `public`, `grouped` (default) or `private`; first match wins; unmatched checks are public under their area's name. See [visibility](web.html#visibility). Areas are `dns mail http tls domains hosts hygiene cloud` |
| `hosts` | `hosts: [{name, url, postfix, knot, wgIgnore}]`, `wgPeers: {pubkey: name}` | thresholds: `disk {80,90}` %, `memory {90,97}` %, `swap {60,90}` %, `load {2,4}` per CPU, `wgHandshake {600,3600}` s, `queueSize {20,200}`, `queueAge {3600,14400}` s, `knotExpiry {1209600,259200}` s, `nixpkgsAge {30,90}` days, `knotZones` (default `dns.zones`); rates over `rateWindow: "5m"`: `cpu {85,95}` %, `memoryStall {10,30}` %, `swapIn {100,1000}` pages/s, `diskBusy {80,95}` %, `ioStall {25,50}` %, `netErrors {1,10}`/s, `netMbps` (off), `unitMemory {85,95}` % of MemoryMax |
| `dns` | `zones`, `primary`, `servers: [{name, addrs}]`, `delegation`, `resolve: {name: [ips]}`, `publicResolver: "1.1.1.1"` | `delegation` is the expected NS names |
| `domains` | `names`, `days {45,14}`, `bootstrap` (IANA), `servers: {tld: rdapBaseURL}` | |
| `tls` | `targets: [{name, host, port, starttls, families, alpn}]`, `days {20,7}` | `port` 443, or 25 with `starttls: "smtp"`; `families` `["4","6"]`; `alpn: "h2"` warns unless h2 is chosen |
| `ct` | `domains` (default `domains.names`), `issuers: ["Let's Encrypt"]`, `domainIssuers: {domain: [...]}`, `names`, `ignore`, `recent: "7d"`, `api`, `tokenSecret: "certspotter_token"` | Certificate Transparency through Cert Spotter; issuers match as substrings |
| `http` | `targets: [{name, url, expectStatus: 200, latency {2,5}}]` | latency in seconds; redirects are not followed |
| `mail.banner` | `servers: [{name, addrs, port: 25, expect}]`, `latency {3,10}` | |
| `mail.openRelay` | `servers`, `helo`, `from`, `to`, `expect: 554` | probe from a host outside the relay's `mynetworks` |
| `mail.blocklists` | `resolver: "127.0.0.1:53"`, `ips`, `lists: [{zone, ipv6, crit}]` | |
| `linode` | `tokenSecret: "linode_token"`, `instances: [{name, id}]`, `uninvoiced`, `transfer {80,95}`, `eventWindow: "24h"` | |
| `cloudflare` | `tokenSecret: "cloudflare_token"`, `zone`, `zoneId`, `accountId`, `expected: [{type, name, content, priority}]`, `watch: [{type, name}]` | without `zoneId` the token also needs Zone Read to look the zone up; `accountId` narrows that lookup when the token sees several accounts |

## Environment

From `services.sitescope.environmentFile`:

| variable | used by |
|---|---|
| `SITESCOPE_AGENT_TOKEN` | the hub and every agent; the same value everywhere |
| `SITESCOPE_HEARTBEAT_URL` | the hub; GET once a minute while healthy |
| `SITESCOPE_CONFIG` | the CLI; config path when `-config` isn't given |

## Generating settings

Settings are plain Nix, so derive them from what the flake already knows
instead of repeating it. For example, with an inventory attrset of hosts
and a directory of zone files:

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
  hosts = {
    hosts = lib.mapAttrsToList (name: h: {
      inherit name;
      url = "http://${h.wg}:9105";
      postfix = h.role == "secondary";
      knot = true;
    }) inventory;
    wgPeers = lib.mapAttrs' (n: h: lib.nameValuePair h.wgPublicKey n) inventory;
  };
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
