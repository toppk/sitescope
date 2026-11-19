<p align="center"><img src="site/assets/logo-512.webp" alt="sitescope" width="160"></p>

# sitescope

A small, fast health monitor for a handful of NixOS hosts, named after HP
SiteScope. One static Go binary:

- `sitescope agent` runs on every host and serves `GET /v1/report` (JSON,
  bearer token) on its wg0 address: disk, memory, swap, load, uptime, failed
  units, booted vs current generation, nixpkgs date, WireGuard handshakes,
  postfix queue, Knot zone status, and counters for CPU, pressure (PSI),
  vmstat, disk and network I/O and per-service cgroup memory. The same data
  is at `GET /metrics` in Prometheus text format, with node_exporter's names
  where they overlap.
- `sitescope hub` runs on one host. It polls the agents, runs the external probes,
  keeps 30+ days of history in `/var/lib/sitescope/history.db` (bbolt), emails
  state changes and a daily digest, pings a dead-man's-switch URL, and serves
  the status page on `127.0.0.1:8470` for a reverse proxy.
- CLI: `unlock`, `lock`, `status`, `vault set|rm|list|set-password`, `config`
  (the effective config, or a check of one), `check`, `probes` (every
  destination the hub contacts, and how often), `verify`, `version`.

Nothing about the infrastructure is hardcoded: every target comes from one
config file, TOML or JSON. On NixOS, the module renders it from
`services.sitescope.settings`.

## Checks

| area (`id` prefix) | what | default interval |
|---|---|---|
| dns (`dns.`) | primary answers SOA for every zone; per zone × secondary × IPv4/IPv6: SOA with `aa`, serial equal to the primary's; TLD delegation lists the expected NS; names resolve to expected IPs on a public resolver | 5m (delegation 1h) |
| dns (`host.*.knot`) | Knot zones loaded, not near expiry, none missing | with agent poll |
| domains (`domain.`) | RDAP registration expiry; warn 45 days, crit 14 | 12h |
| tls (`tls.`) | certificate days left over HTTPS or SMTP STARTTLS, per IP family, chain verified; warn 20, crit 7; optional ALPN (`alpn = "h2"`) | 6h |
| tls (`ct.`) | Certificate Transparency (Cert Spotter): valid certificates for each domain from an unexpected CA (crit) or for unexpected names (warn) | 24h, domains spread over the day |
| http (`http.`) | status code and latency | 1m |
| mail (`mail.`) | SMTP banner per address; daily open-relay probe expecting 554; DNS blocklists through the local unbound | 5m / 24h / 1h |
| mail (`host.*.postfix`) | queue size and oldest message age | with agent poll |
| hosts (`host.`) | agent reachable, disk, memory (cache excluded), swap, load per CPU, failed units, WireGuard handshake age; 5-minute rates of CPU, memory pressure (PSI stalls, swap-in, OOM kills), disk I/O, network; services against their MemoryMax | 1m |
| hygiene (`host.*.reboot`, `.nixpkgs`) | kernel/initrd changed since boot; nixpkgs age (warn 30 days) | with agent poll |
| cloud (`linode.`, `cloudflare.`) | Linode balance / payment due, accrued charges, transfer, maintenance and notices, notable events, instance status; Cloudflare records vs. expected set; Cloudflare API token expiry (daily) | 1h, needs vault |
| hub (`hub.vault`) | vault still locked `hub.lockedAfter` (15m) after a start or `sitescope lock`: warn | every tick |

Every check has `ok`, `warn` or `crit` (plus `unknown`, and `locked` while the
vault is locked). A move into warn/crit must repeat `retries` more times
(`retryInterval` apart) before it counts. Recovery counts at once. Runs land
on a `hub.tick` grid (1m) at a fixed phase per check, so the hub sleeps
between steps and targets see an even rate; checks sharing a rate-limited
API (CT) are spread evenly over their interval.

## Alerts

Changes from each batch of checks go out as one email, sent via SMTP to
`127.0.0.1:25` (postfix signs it). Once a check has been notified, its next
change waits at least `renotifyInterval` (default 1h). A check that flaps back
to the notified status sends nothing. The first sighting of a healthy check is
silent. A check stuck in unknown for `unknownAfter` (default 1h) is reported
once, unless its agent is down. A digest of everything not ok goes out once a day after
`alerts.digestTime` (skipped on the day of a start after that time).
When some check needs a vault secret, startup sends "sitescope started on
<host> - vault LOCKED, run sitescope unlock", and `hub.vault` warns if it is
still locked 15 minutes later.

Every `hub.heartbeatInterval` (default 1m) with no store errors the hub GETs
`SITESCOPE_HEARTBEAT_URL`, e.g. a dead-man's-switch check with a matching
period and some grace.

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
| `cloudflare_token` | Cloudflare API token | Zone → DNS → Read, zone resources: Include → Specific zone → your zone. Add Zone → Zone → Read only if `cloudflare.zoneId` is not set (it's needed to look the zone up by name). To watch other tokens add User → API Tokens → Read (Account → Account API Tokens → Read for account-owned tokens); it shows names and expiry, never token values |
| `certspotter_token` | optional Cert Spotter API key | raises the CT rate limit above 10 requests an hour |
| `admin_password_hash` | written by `vault set-password` | |

Names are configurable (`linode.tokenSecret`, `cloudflare.tokenSecret`, `ct.tokenSecret`).

## Web

- `/`: public. Overall status and one traffic light per service, plus the
  vault-locked banner. Each check is `public` (its own row, under a label
  from `labels`), `grouped` (folded into its service's light) or `private`
  (not shown, not counted). `public` is an ordered list of rules matched by
  area or check id glob; first match wins, and unmatched checks are public
  under their area's name (so with no rules everything is listed, by check
  name). Messages are never shown; the footer shows sitescope's version.
- `/detail`, `/detail/check?id=…`, `/api/status`: HTTP basic auth, user
  `admin`, password checked against the bcrypt hash in the vault. Read-only.
  Each check has its last message, retries, 30-day strip and history.
- `/status.json`: the public page as JSON, same facts.
- `/healthz`: 200 while the scheduler is on schedule.

## Configuration

One file, picked by its extension: TOML, written by people, or JSON, for
generated configs. On NixOS the same keys go in `services.sitescope.settings`,
written in Nix. Every key is optional:

```toml
[hub]
publicURL = "https://status.example.org"

[alerts]
enabled = true
from = "sitescope@example.org"
to = ["ops@example.org"]
digestTime = "08:00"

[[host]]
name = "alpha"
url = "http://10.0.0.1:9105"
knot = true

[hosts]
disk = { warn = 85, crit = 95 }   # thresholds shared by every host
diskBusy = { warn = 95, crit = "off" }

[dns]
zones = ["example.org"]
primary = "10.0.0.1"

[[tls.targets]]
name = "www.example.org"

[[http.targets]]
name = "www"
url = "https://www.example.org/healthz"
```

- On NixOS, the module renders `settings` to JSON, and the system build
  checks it. `sitescope config -format nix` prints a config as settings.
- An unknown or misspelled key fails at load, naming it:
  `hosts.swapin: unknown key (did you mean swapIn?)`.
- `sitescope config -config FILE` prints the effective config, every
  default filled in. `sitescope config -defaults` prints every key.
- Secrets come from the environment (`SITESCOPE_AGENT_TOKEN`,
  `SITESCOPE_HEARTBEAT_URL`, …) and the vault, never from the config.

The [configuration reference](https://toppk.github.io/sitescope/configuration.html)
lists every key, and every example on the site comes in TOML, JSON and Nix.
[Using sitescope on NixOS](https://toppk.github.io/sitescope/nixos.html#using-sitescope-on-nixos)
shows settings generated from an inventory.

Try a config without the daemon: `sitescope check -config FILE [-match dns.soa]`
runs every non-credential check once and exits 2 if any is crit.

## Install

Each [release](https://github.com/toppk/sitescope/releases) has static
binaries for Linux on x86-64 and arm64, with `SHA256SUMS`:

```sh
v=1.6.0
curl -fLO https://github.com/toppk/sitescope/releases/download/v$v/sitescope-$v-linux-amd64.tar.gz
curl -fLO https://github.com/toppk/sitescope/releases/download/v$v/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf sitescope-$v-linux-amd64.tar.gz
./sitescope-$v-linux-amd64/sitescope version
```

From source: `nix build github:toppk/sitescope/v1.6.0`, or
`go install github.com/toppk/sitescope@v1.6.0` (which reports
`1.6.0+dev`). On NixOS, use the flake's module; see
[Getting started](https://toppk.github.io/sitescope/getting-started.html).

## Development

```sh
go test ./...
nix build            # runs the tests in the sandbox
nix flake check      # package + module evaluated as hub (with local agent) and agent
```

Bump `vendorHash` in `nix/package.nix` whenever `go.sum` changes.

Docs: `site/build.sh _site` (pandoc), published by `.github/workflows/pages.yml`.

## License

MIT; see [LICENSE](LICENSE).
