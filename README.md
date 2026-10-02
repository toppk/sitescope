<p align="center"><img src="site/assets/logo-512.webp" alt="sitescope" width="160"></p>

# sitescope

A small, fast health monitor for a handful of NixOS hosts, named after HP
SiteScope. One static Go binary:

- `sitescope agent` runs on every host and serves `GET /v1/report` (JSON,
  bearer token) on its wg0 address: disk, memory, swap, load, uptime, failed
  units, booted vs current generation, nixpkgs date, WireGuard handshakes,
  postfix queue, Knot zone status.
- `sitescope hub` runs on one host. It polls the agents, runs the external probes,
  keeps 30+ days of history in `/var/lib/sitescope/history.db` (bbolt), emails
  state changes and a daily digest, pings a dead-man's-switch URL, and serves
  the status page on `127.0.0.1:8470` for a reverse proxy.
- CLI: `unlock`, `lock`, `status`, `vault set|rm|list|set-password`, `check`.

Nothing about the infrastructure is hardcoded: every target comes from the
JSON config that the NixOS module renders from `services.sitescope.settings`.

## Checks

| area (`id` prefix) | what | default interval |
|---|---|---|
| dns (`dns.`) | primary answers SOA for every zone; per zone × secondary × IPv4/IPv6: SOA with `aa`, serial equal to the primary's; TLD delegation lists the expected NS; names resolve to expected IPs on a public resolver | 5m (delegation 1h) |
| dns (`host.*.knot`) | Knot zones loaded, not near expiry, none missing | with agent poll |
| domains (`domain.`) | RDAP registration expiry; warn 45 days, crit 14 | 12h |
| tls (`tls.`) | certificate days left over HTTPS or SMTP STARTTLS, per IP family, chain verified; warn 20, crit 7 | 6h |
| http (`http.`) | status code and latency | 1m |
| mail (`mail.`) | SMTP banner per address; daily open-relay probe expecting 554; DNS blocklists through the local unbound | 5m / 24h / 1h |
| mail (`host.*.postfix`) | queue size and oldest message age | with agent poll |
| hosts (`host.`) | agent reachable, disk, memory, swap, load per CPU, failed units, WireGuard handshake age | 1m |
| hygiene (`host.*.reboot`, `.nixpkgs`) | kernel/initrd changed since boot; nixpkgs age (warn 30 days) | with agent poll |
| cloud (`linode.`, `cloudflare.`) | Linode balance / payment due, accrued charges, transfer, maintenance and notices, notable events, instance status; Cloudflare records vs. expected set | 1h, needs vault |

Every check has `ok`, `warn` or `crit` (plus `unknown`, and `locked` while the
vault is locked). A move into warn/crit must repeat `retries` more times
(`retryInterval` apart) before it counts. Recovery counts at once.

## Alerts

Changes are batched every 30 seconds into one email, sent via SMTP to
`127.0.0.1:25` (postfix signs it). Once a check has been notified, its next
change waits at least `renotifyInterval` (default 1h). A check that flaps back
to the notified status sends nothing. The first sighting of a healthy check is
silent. A check stuck in unknown for `unknownAfter` (default 1h) is reported
once, unless its agent is down. A digest of everything not ok goes out once a day after
`alerts.digestTime` (skipped on the day of a start after that time). Startup always sends "sitescope started on <host> - vault
LOCKED, run sitescope unlock".

After every minute with no store errors the hub GETs
`SITESCOPE_HEARTBEAT_URL`, e.g. a dead-man's-switch check with a period of 1
minute and a grace of 5.

## Vault

Credentials live in `/var/lib/sitescope/vault.age`, encrypted with age in
passphrase mode (scrypt, work factor 2^15, which needs 32 MiB transiently; the
age default 2^18 would need 256 MiB and exceed MemoryMax). Decrypted values
only exist in an mlocked, MADV_DONTDUMP buffer outside the Go heap. The buffer
is zeroed on `lock`, on SIGTERM and on exit. The process sets PR_SET_DUMPABLE=0 and
RLIMIT_CORE=0. Known limits: a value is copied to the heap for the moment it
is placed in an `Authorization` header, and age's own decryption chunk buffer
is heap memory.

The hub starts locked. Checks that need a secret report `locked` and don't
count against any status light; everything else runs. The detail view and
`/api/status` answer 503 while locked, because the admin password hash is in
the vault.

```sh
# as an operator in the sitescope-admin group, on the hub host
sitescope unlock          # prompts for the passphrase on the tty, sends it over /run/sitescope/control.sock
sitescope status
sitescope lock

# editing the file needs write access to /var/lib/sitescope
sudo -u sitescope sitescope vault set linode_token      # value from stdin, or prompted without echo
sudo -u sitescope sitescope vault set cloudflare_token
sudo -u sitescope sitescope vault set-password          # bcrypt hash for the detail view (user "admin")
sudo -u sitescope sitescope vault list
sudo -u sitescope sitescope vault rm NAME
sitescope unlock          # again, to load the edited vault into the running hub
```

The first `vault set` creates the vault and asks for the new passphrase twice.

### Secrets and minimum token scopes

| name | what | minimum scope |
|---|---|---|
| `linode_token` | Linode personal access token | Account: Read Only, Events: Read Only, Linodes: Read Only; everything else No Access |
| `cloudflare_token` | Cloudflare API token | Zone → DNS → Read, zone resources: Include → Specific zone → your zone. Add Zone → Zone → Read only if `cloudflare.zoneId` is not set (it's needed to look the zone up by name) |
| `admin_password_hash` | written by `vault set-password` | |

Names are configurable (`linode.tokenSecret`, `cloudflare.tokenSecret`).

## Web

- `/`: public. Overall status and one traffic light per service, plus the
  vault-locked banner. Each check is `public` (its own row, under a label
  from `labels`), `grouped` (folded into its service's light) or `private`
  (not shown, not counted). `public` is an ordered list of rules matched by
  area or check id glob; first match wins, and unmatched checks are public
  under their area's name (so with no rules everything is listed). Messages, hostnames,
  addresses and versions are never shown.
- `/detail`, `/detail/check?id=…`, `/api/status`: HTTP basic auth, user
  `admin`, password checked against the bcrypt hash in the vault. Read-only.
  Each check has its last message, retries, 30-day strip and history.
- `/status.json`: the public page as JSON, same facts.
- `/healthz`: 200 while the scheduler is ticking.

## Configuration

The module fills in listen addresses, paths, command locations and the
hostname. Everything else goes in `services.sitescope.settings`:

```nix
let
  inventory = import ./inventory.nix;
  zones = map (f: lib.removeSuffix ".zone" f)
    (lib.filter (lib.hasSuffix ".zone") (lib.attrNames (builtins.readDir ./zones)));
  relays = lib.filterAttrs (_: h: h.role == "secondary") inventory;
  nixHosts = lib.filterAttrs (_: h: h.ipv4 != null) inventory;
  addrs = h: [ h.ipv4 h.ipv6 ];
in
{
  alerts = { enabled = true; from = "sitescope@example.org"; to = [ "ops@example.org" ]; digestTime = "08:00"; };
  hub.publicURL = "https://status.example.org";
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
    }) nixHosts;
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
  tls.targets = lib.concatMap (h: [ { name = h.publicName; } { name = h.publicName; starttls = "smtp"; } ])
    (lib.attrValues relays) ++ [ { name = "www.example.org"; } { name = "status.example.org"; } ];
  http.targets = [
    { name = "www"; url = "https://www.example.org/healthz"; }
    { name = "status"; url = "https://status.example.org/healthz"; }
  ];
  mail = {
    banner.servers = lib.mapAttrsToList (name: h: { inherit name; addrs = addrs h; expect = h.publicName; }) relays;
    openRelay.servers = lib.mapAttrsToList (name: h: { inherit name; addrs = [ h.ipv4 ]; }) relays;
    blocklists = {
      ips = lib.concatMap addrs (lib.attrValues relays);
      lists = [
        { zone = "zen.spamhaus.org"; ipv6 = true; crit = true; }
        { zone = "bl.spamcop.net"; }
        { zone = "b.barracudacentral.org"; }
        { zone = "bl.mailspike.net"; }
      ];
    };
  };
  linode.instances = [ { name = "alpha"; id = 12345678; } { name = "bravo"; id = 23456789; } ];
  cloudflare = {
    zone = "example.org";
    zoneId = "…";
    expected = [ { type = "A"; name = "www.example.org"; content = "192.0.2.10"; } /* … */ ];
  };
}
```

Reference (all optional; defaults shown):

| key | default | notes |
|---|---|---|
| `defaults` | `{interval: "5m", timeout: "10s", retries: 2, retryInterval: "30s"}` | every section and HTTP target takes the same four keys |
| `hub` | `listen`, `stateDir`, `vault`, `controlSocket`, `controlGroup`, `hostname` (set by the module), `title: "Status"`, `publicURL`, `refresh: 60`, `retentionDays: 35`, `sampleEvery: "15m"`, `concurrency: 8` | history keeps every status change plus one sample per `sampleEvery` |
| `alerts` | `enabled: false`, `smtp: "127.0.0.1:25"`, `from`, `to`, `subjectPrefix: "[sitescope]"`, `renotifyInterval: "1h"`, `unknownAfter: "1h"` (negative disables), `digestTime` (`"HH:MM"`, local time) | |
| `public` | every check public, under its area | ordered rules `[{name, areas, checks, visibility, labels}]`, visibility `public`/`grouped`/`private`; areas: dns mail http tls domains hosts hygiene cloud |
| `hosts` | `hosts: [{name, url, postfix, knot, wgIgnore}]`, `wgPeers: {pubkey: name}`, thresholds `disk {80,90}` %, `memory {90,97}` %, `swap {60,90}` %, `load {2,4}` per CPU, `wgHandshake {600,3600}` s, `queueSize {20,200}`, `queueAge {3600,14400}` s, `knotExpiry {14d,3d}` s, `nixpkgsAge {30,90}` days, `knotZones` (default `dns.zones`) | thresholds are `{warn, crit}`, 0 disables a bound |
| `dns` | `zones`, `primary`, `servers: [{name, addrs}]`, `delegation`, `resolve: {name: [ips]}`, `publicResolver: "1.1.1.1"` | |
| `domains` | `names`, `days {45,14}`, `bootstrap` (IANA), `servers: {tld: rdapBaseURL}` | .us and .co, missing from the IANA file, have built-in fallbacks |
| `tls` | `targets: [{name, host, port, starttls: ""\|"smtp", families: ["4","6"]}]`, `days {20,7}` | |
| `http` | `targets: [{name, url, expectStatus: 200, latency {2,5} s}]` | redirects are not followed |
| `mail.banner` | `servers: [{name, addrs, port: 25, expect}]`, `latency {3,10}` s | |
| `mail.openRelay` | `servers`, `helo`, `from`, `to`, `expect: 554` | probe from a host outside the relay's `mynetworks` |
| `mail.blocklists` | `resolver: "127.0.0.1:53"`, `ips`, `lists: [{zone, ipv6, crit}]` | `127.255.255.x` answers (refused) don't count as listed |
| `linode` | `tokenSecret: "linode_token"`, `instances: [{name, id}]`, `uninvoiced {}` USD, `transfer {80,95}` %, `eventWindow: "24h"` | |
| `cloudflare` | `tokenSecret: "cloudflare_token"`, `zone`, `zoneId`, `expected: [{type, name, content, priority}]`, `watch: [{type, name}]` | missing expected record: crit. Any other record with an expected name/type (or a watched one): warn |
| `agent` | `listen`, `wgInterface: "wg0"`, `postfix`, `knot`, `knotSocket`, command paths | set by the module |

Environment (`environmentFile`): `SITESCOPE_AGENT_TOKEN` (hub and agents, the
same value), `SITESCOPE_HEARTBEAT_URL` (hub).

Try a config without the daemon: `sitescope check -config FILE [-match dns.soa]`
runs every non-credential check once and exits 2 if any is crit.

## Development

```sh
go test ./...
nix build            # runs the tests in the sandbox
nix flake check      # package + module evaluated as hub (with local agent) and agent
```

Bump `vendorHash` in `nix/package.nix` whenever `go.sum` changes.

Docs: `site/build.sh _site` (pandoc), published by `.github/workflows/pages.yml`.
