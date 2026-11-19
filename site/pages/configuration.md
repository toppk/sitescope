---
title: Configuration
eyebrow: Use
lede: One file, TOML or JSON, or NixOS settings in Nix. Every key is optional, and nothing about your hosts is built in.
description: Every sitescope configuration key with its default, how a config is checked, and the environment variables it reads.
---

## The file

sitescope reads one config file, `.toml` or `.json`, picked by its
extension. Both have the same keys, defaults and checks, and so do NixOS
`settings`, written in Nix. Each example on this site comes in all three:
pick a tab, and every example switches to it.

- On NixOS, the module renders `services.sitescope.settings` to JSON. See
  [Using sitescope on NixOS](nixos.html#using-sitescope-on-nixos).
- Elsewhere, write `config.toml` yourself. See
  [Without NixOS](standalone.html).

The daemons take `-config FILE`. The CLI reads `-config FILE`, then
`$SITESCOPE_CONFIG`, then `/etc/sitescope/config.toml` or
`/etc/sitescope/config.json`. If both of those exist, it asks you to
remove one.

A small hub config:

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

[[host]]
name = "bravo"
url = "http://10.0.0.2:9105"
postfix = true

[dns]
zones = ["example.org"]
primary = "10.0.0.1"

[[tls.targets]]
name = "www.example.org"

[[http.targets]]
name = "www"
url = "https://www.example.org/healthz"
```

## Values

- **Durations** are strings like `"90s"`, `"5m"` or `"12h"`, or a number
  of seconds. `hub.lockedAfter` and `alerts.unknownAfter` also take
  `"off"`.
- **Thresholds** are `{ warn = …, crit = … }`. A bound you leave out keeps
  its default, and `"off"` turns it off: `diskBusy = { warn = 95, crit = "off" }`
  warns at 95% and never goes crit.
- **Lists of entries** are either a table per entry, as in `[[host]]`, or
  one line each, as in `units = [{ name = "sshd.service" }, …]`. TOML
  reads both the same way.
- **A section** is on when it's present. To turn one off, leave it out.

## Checking a config

Keys are exact, case included. An unknown key fails at load with its path
and the closest known key, and every problem is listed at once:

```text
sitescope: config: 2 problems:
  hosts.swapin: unknown key (did you mean swapIn?)
  host[0].unitz: unknown key (did you mean units?)
```

A key renamed in a release fails the same way and names its new form, as
in `hosts.hosts: renamed in 1.5.0: use host`. A TOML syntax error gives
its line.

- `sitescope config -config FILE -check` loads the config and builds its
  checks, and prints only the check count. It needs no secrets and opens
  no files the config names.
- `sitescope config -config FILE` prints the effective config as TOML,
  with every default filled in. `-format json` prints it as JSON, and
  `-format nix` as NixOS settings.
- `sitescope config -defaults` prints every key with its built-in
  default: the reference below, without the comments.
- The NixOS module runs `-check` on the rendered settings when the system
  builds, so a typo fails `nixos-rebuild` before anything deploys.

## Timing

`[defaults]` sets timing for every check. Every section, and each target
within one, can override it with the same four keys:

| key | default | |
|---|---|---|
| `interval` | `"5m"` | time between runs (some sections have their own default, see [Checks](checks.html)) |
| `timeout` | `"10s"` | per run |
| `retries` | `2` | further failures needed before warn or crit is committed |
| `retryInterval` | `"1m"` | time between those retries, rounded up to the next `hub.tick` |

## Every key

Every section, with its defaults, in TOML; `sitescope config -defaults
-format json` or `-format nix` prints it in the other two. A list shows one
entry, with every key that entry takes. An empty string, list or table means none, or that the
comment gives the default. [Checks](checks.html) says what each section
checks.

<!-- toml only: TestConfigReference checks this block against "sitescope config -defaults", comments aside. -->
```toml
[hub]
# The NixOS module sets listen, stateDir, vault, controlSocket, controlGroup and hostname.
listen = "127.0.0.1:8470"  # the status page; put a reverse proxy in front
stateDir = "/var/lib/sitescope"  # history.db lives here
controlSocket = "/run/sitescope/control.sock"  # for unlock, lock and status
controlGroup = ""  # group that may use the socket
vault = "/var/lib/sitescope/vault.age"  # default: stateDir/vault.age
publicURL = ""  # used in alert mail
hostname = "host.example.org"  # default: this machine's hostname
title = "Status"
refresh = 60  # seconds between page reloads
docsURL = "https://toppk.github.io/sitescope/"  # the page's docs link
retentionDays = 35  # history kept
sampleEvery = "15m"  # one history sample per check this often, besides every change
tick = "1m"  # the scheduler's grid
heartbeatInterval = "1m"  # GET $SITESCOPE_HEARTBEAT_URL this often while healthy
lockedAfter = "15m"  # hub.vault warns once the vault is locked this long; "off" removes the check
concurrency = 8  # checks running at once

[agent]
listen = ""  # address:port; the NixOS module sets it
wgInterface = "wg0"  # WireGuard interface for handshake stats
postfix = false  # report the postfix queue
knot = false  # report Knot zone status
knotSocket = "/run/knot/knot.sock"
tlsCert = ""  # with tlsKey: serve HTTPS, re-read when the file changes
tlsKey = ""
wgPeers = {}  # pubkey = name, for metric labels; default hosts.wgPeers
systemctl = "systemctl"  # command paths; the NixOS module sets them
wg = "wg"
postqueue = "postqueue"
knotc = "knotc"

[alerts]
enabled = false
smtp = "127.0.0.1:25"
from = ""  # required with enabled
to = []  # required with enabled
subjectPrefix = "[sitescope]"
renotifyInterval = "1h"  # at most one email per check this often
unknownAfter = "1h"  # report a check stuck in unknown this long; "off" never does
digestTime = ""  # "HH:MM", local time; empty: no digest
# ntfy pushes to $SITESCOPE_NTFY_URL: min is "crit" or "warn"; details adds check names.
ntfy = { enabled = false, min = "crit", details = false }

[defaults]
# Every section, and each target, takes these four keys too.
interval = "5m"
timeout = "10s"
retries = 2  # further failures before warn or crit is committed
retryInterval = "1m"  # between those retries, rounded up to hub.tick

[[public]]
# Ordered rules; each check takes the first that matches.
# Unmatched checks are public, under their area's name.
name = ""
areas = []  # match by area: dns mail http tls domains hosts devices hygiene cloud hub
checks = []  # or by check id glob, e.g. "host.*.disk"
visibility = "grouped"  # "public": a row per check; "grouped": one light; "private": hidden
labels = {}  # check id = public label

[hosts]
# Shared by every host; a threshold's unset bound keeps its default.
wgPeers = {}  # pubkey = name
disk = { warn = 80, crit = 90 }  # percent used, per mount
memory = { warn = 90, crit = 97 }  # percent used, page cache excluded
swap = { warn = 60, crit = 90 }  # percent used
load = { warn = 2, crit = 4 }  # load average per CPU
wgHandshake = { warn = 600, crit = 3600 }  # seconds since a peer's handshake
queueSize = { warn = 20, crit = 200 }  # postfix messages
queueAge = { warn = 3600, crit = 14400 }  # seconds, oldest queued message
knotExpiry = { warn = 1209600, crit = 259200 }  # seconds until a zone expires
nixpkgsAge = { warn = 30, crit = 90 }  # days; NixOS hosts
updatesAge = { warn = 30, crit = 90 }  # days since the package database changed; other hosts
rateWindow = "5m"  # the rates below are averaged over this
cpu = { warn = 85, crit = 95 }  # percent busy
memoryStall = { warn = 10, crit = 30 }  # percent of time some task waited on memory
swapIn = { warn = 100, crit = 1000 }  # pages per second
diskBusy = { warn = 80, crit = 95 }  # percent of time a device was busy
ioStall = { warn = 25, crit = 50 }  # percent of time some task waited on I/O
netErrors = { warn = 1, crit = 10 }  # errors and drops per second
netMbps = {}  # megabits per second; off unless set
unitMemory = { warn = 85, crit = 95 }  # percent of a service's MemoryMax
knotZones = []  # default dns.zones

[[host]]
# One [[host]] per host.
name = ""
url = ""  # the agent's report URL; not with local
postfix = false  # check the postfix queue
knot = false  # check Knot zones
os = ""  # os-release ID; default "nixos". Others drop the NixOS checks
ca = ""  # PEM file that verifies an https agent URL
tokenEnv = ""  # variable with this agent's token; default SITESCOPE_AGENT_TOKEN
wgIgnore = []  # WireGuard peers whose handshake age doesn't matter
# wireguard = false drops the handshake check (default on).
# A unit: severity "crit" (default) or "warn"; maxAge bounds a timer's last run.
units = [
  { name = "", user = false, severity = "", maxAge = "0s" },
]
local = false  # the hub's own host, collected in-process; no url
skip = []  # checks not to create, e.g. ["swap"]
# disks."/data" = { free = { warn = 500, crit = 100 }, used = {}, inodes = {}, ignore = false }
# free is GiB available; used and inodes are percent and replace hosts.disk for that mount.
disks = {}  # per-mount disk rules, below

[dns]
zones = []  # zones served
primary = ""  # the primary's address
servers = [
  { name = "", addrs = [] },
]
delegation = []  # expected NS names at the parent
publicResolver = "1.1.1.1"  # for resolve and delegation
resolve = {}  # name = [addresses] it must resolve to

[domains]
names = []  # registered domains
days = { warn = 45, crit = 14 }  # days left on the registration
bootstrap = "https://data.iana.org/rdap/dns.json"  # IANA's RDAP bootstrap file
servers = {}  # tld = RDAP base URL, for TLDs missing from it

[tls]
days = { warn = 20, crit = 7 }  # days left on the certificate

[[tls.targets]]
# One [[tls.targets]] per name and port.
name = ""
host = ""  # default: name
port = 0  # default 443, or 25 with starttls
starttls = ""  # "" or "smtp"
families = []  # default ["4", "6"]
alpn = ""  # e.g. "h2": warn unless the server chooses it

[ct]
domains = []  # default domains.names
issuers = ["Let's Encrypt"]  # allowed issuers, matched as substrings
domainIssuers = {}  # domain = [more issuers], e.g. a CDN's
names = []  # expected DNS names, globs; empty skips the name check
ignore = []  # certificate SHA-256s already looked at
recent = "168h"  # certificates this new are listed in the message
api = "https://api.certspotter.com/v1"
tokenSecret = "certspotter_token"  # optional Cert Spotter key in the vault

[[http.targets]]
name = ""
url = ""
expectStatus = 0  # default 200, or any 3xx with redirect
latency = { warn = 2, crit = 5 }  # seconds
ca = ""  # PEM file of the only CA trusted for this URL
body = ""  # text the response must contain
redirect = ""  # where it must redirect; redirects aren't followed

[mail.banner]
servers = [
  { name = "", addrs = [], port = 0, expect = "" },
]
latency = { warn = 3, crit = 10 }  # seconds

[mail.openRelay]
servers = [
  { name = "", addrs = [], port = 0, expect = "" },
]
helo = "host.example.org"  # default hub.hostname
from = "relay-probe@example.com"
to = "relay-probe@example.net"
expect = 554  # the refusal code; probe from outside the relay's mynetworks

[mail.blocklists]
resolver = "127.0.0.1:53"  # a local resolver; public ones are refused by most lists
ips = []  # addresses to look up
lists = [
  { zone = "", ipv6 = false, crit = false },
]

[ping]
loss = { warn = 50, crit = 100 }  # percent of echoes lost; per-target loss overrides
rtt = {}  # milliseconds, average; off unless set

[[ping.targets]]
# loss and rtt here override ping.loss and ping.rtt.
name = ""
host = ""  # default: name
count = 3  # echoes per run
family = ""  # "4" or "6"; default the first address
seenWithin = "0s"  # ok while it answered this recently, for devices that sleep
loss = { warn = 50, crit = 100 }
rtt = {}

[tcp]
targets = [
  { name = "", host = "", port = 0, seenWithin = "0s" },
]

[ipp]
targets = [  # url is ipp:// or ipps://, port 631 unless given
  { name = "", url = "", ca = "" },
]

[linode]
tokenSecret = "linode_token"  # read-only token in the vault
api = "https://api.linode.com/v4"
instances = [
  { name = "", id = 0 },
]
uninvoiced = {}  # accrued charges, USD; off unless set
transfer = { warn = 80, crit = 95 }  # percent of the transfer pool
eventWindow = "24h"  # notable events this recent

[cloudflare]
tokenSecret = "cloudflare_token"  # read-only token in the vault
api = "https://api.cloudflare.com/client/v4"
zone = ""
zoneId = ""  # without it the token also needs Zone Read
accountId = ""  # narrows the zone lookup
expected = [  # missing: crit; priority = N for MX
  { type = "", name = "", content = "" },
]
watch = [  # any other record of these: warn
  { type = "", name = "", content = "" },
]
tokens = []  # token names to watch for expiry; default every active one
tokenDays = { warn = 30, crit = 7 }  # days left on a watched token
```

## Environment

Secrets never go in the config. They come from the environment: on NixOS, from
`services.sitescope.environmentFile`; elsewhere, from the unit's `EnvironmentFile`.

| variable | used by |
|---|---|
| `SITESCOPE_AGENT_TOKEN` | the hub and every agent; one shared value, except for hosts that set `tokenEnv` |
| a host's `tokenEnv` | the hub, for that agent; on the agent itself it is still `SITESCOPE_AGENT_TOKEN` |
| `SITESCOPE_NTFY_URL` | the hub, with `alerts.ntfy.enabled`: the ntfy server and topic, e.g. `https://ntfy.sh/<secret topic>` |
| `SITESCOPE_NTFY_TOKEN` | the hub, optional: an ntfy access token |
| `SITESCOPE_HEARTBEAT_URL` | the hub; GET every `hub.heartbeatInterval` while healthy |
| `SITESCOPE_CONFIG` | the CLI; config path when `-config` isn't given |

