---
title: Agent report
eyebrow: Reference
lede: What an agent serves. A JSON report for the hub, and the same facts as Prometheus metrics, so anything that can reach wg0 and holds the token can read them too.
description: The JSON schema of the sitescope agent's /v1/report endpoint.
---

## Endpoint

```sh
curl -H "Authorization: Bearer $SITESCOPE_AGENT_TOKEN" http://10.0.0.3:9105/v1/report
```

`GET /v1/report` returns the report, collected at most every 10 seconds
and cached in between. `GET /metrics` renders the same report in
Prometheus text format. `GET /healthz` answers 200 without a token.

## Fields

| field | type | |
|---|---|---|
| `host` | string | hostname |
| `time` | RFC 3339 | when it was collected |
| `uptimeSec` | number | |
| `load` | [3]number | 1, 5 and 15 minute load |
| `cpus` | int | |
| `memory` | object | `totalKB`, `availableKB`, `freeKB`, `buffersKB`, `cachedKB`, `shmemKB`, `dirtyKB`, `swapTotalKB`, `swapFreeKB` |
| `disks` | array | `device`, `mount`, `fsType`, `totalBytes`, `availBytes`, `usedPct`, `inodesPct`, `files`, `filesFree`; real filesystems only, one per device |
| `failedUnits` | []string | from `systemctl list-units --state=failed` |
| `system` | object | `booted`, `current` (store paths), `rebootNeeded`, `nixosVersion`, `nixpkgsDate` (`YYYYMMDD`) |
| `wireguard` | array | `publicKey`, `latestHandshake` (Unix seconds, 0 = never), `rxBytes`, `txBytes` |
| `postfix` | object | `messages`, `queues` (per queue name), `oldestAgeSec`; only when enabled |
| `knot` | array | `name`, `role`, `serial`, `expiresInSec` (-1 when not a secondary); only when enabled |
| `counters` | object | cumulative since boot: `bootTime`, `cpu` (per CPU, seconds per mode), `pressure` (`cpu`, `memory`, `io`: `someTotalUs`, `fullTotalUs`, `someAvg60`, `fullAvg60`), `vmstat` (`oomKill`, `pswpin`, `pswpout`, `pgmajfault`), `disks` (whole devices: `reads`, `writes`, `readBytes`, `writtenBytes`, `ioTimeMs`), `net` (all but `lo` and `veth*`: bytes, errors and drops each way) |
| `units` | array | each system service's cgroup memory: `unit`, `bytes`, `maxBytes` (only with a MemoryMax) |
| `errors` | object | section name → error, for each section that couldn't be collected |

A failure in one section leaves the rest of the report intact.

## Metrics

`/metrics` uses node_exporter's names, types, labels and units wherever
they measure the same thing, so standard dashboards and alert rules work
unchanged and a Prometheus or VictoriaMetrics can scrape agents as if
they were node_exporters:

```yaml
scrape_configs:
  - job_name: sitescope
    authorization: { credentials_file: /run/secrets/sitescope-agent-token }
    static_configs:
      - targets: [ "10.0.0.1:9105", "10.0.0.2:9105", "10.0.0.3:9105" ]
```

| family | metrics |
|---|---|
| CPU | `node_cpu_seconds_total{cpu,mode}`, `node_load1`, `node_load5`, `node_load15` |
| memory | `node_memory_{MemTotal,MemAvailable,MemFree,Buffers,Cached,Shmem,Dirty,SwapTotal,SwapFree}_bytes` |
| pressure | `node_pressure_{cpu,memory,io}_waiting_seconds_total`, `node_pressure_{memory,io}_stalled_seconds_total` |
| vmstat | `node_vmstat_{oom_kill,pswpin,pswpout,pgmajfault}` |
| filesystems | `node_filesystem_{size_bytes,avail_bytes,files,files_free}{device,fstype,mountpoint}` |
| disks | `node_disk_{reads_completed,writes_completed,read_bytes,written_bytes,io_time_seconds}_total{device}` |
| network | `node_network_{receive,transmit}_{bytes,errs,drop}_total{device}` |
| time | `node_boot_time_seconds`, `node_time_seconds` |
| services | `sitescope_systemd_units_failed`, `sitescope_systemd_unit_memory_bytes{unit}`, `sitescope_systemd_unit_memory_max_bytes{unit}` |
| postfix | `sitescope_postfix_queue_messages{queue}`, `sitescope_postfix_queue_oldest_seconds` |
| Knot | `sitescope_knot_zones`, `sitescope_knot_zone_serial{zone}`, `sitescope_knot_zone_expires_seconds{zone}` |
| WireGuard | `sitescope_wireguard_latest_handshake_seconds{peer}`, `sitescope_wireguard_{received,sent}_bytes_total{peer}` |
| hygiene | `sitescope_reboot_required`, `sitescope_nixpkgs_age_seconds` |
| agent | `sitescope_agent_build_info{version}`, `sitescope_agent_collect_errors_total{collector}` |

There is no host or instance label; the scraper adds one. WireGuard peers
are labelled with host names from `agent.wgPeers` (or `hosts.wgPeers`),
never keys; an unnamed peer is `unnamed1`, `unnamed2`, …. A collector that
fails counts in `sitescope_agent_collect_errors_total` and leaves its
metrics out; the response is still 200.

## Example

```json
{
  "host": "b",
  "time": "2026-10-01T12:00:00Z",
  "uptimeSec": 1209600,
  "load": [0.08, 0.05, 0.01],
  "cpus": 1,
  "memory": { "totalKB": 2014000, "availableKB": 1402000, "swapTotalKB": 1048572, "swapFreeKB": 1048572 },
  "disks": [ { "mount": "/", "fsType": "ext4", "totalBytes": 52521566208, "availBytes": 41022046208, "usedPct": 21.9, "inodesPct": 6.1 } ],
  "failedUnits": [],
  "system": {
    "booted": "/nix/store/…-nixos-system-b-26.05.20260920.abcdef0",
    "current": "/nix/store/…-nixos-system-b-26.05.20260920.abcdef0",
    "rebootNeeded": false,
    "nixosVersion": "26.05.20260920.abcdef0 (Yarara)",
    "nixpkgsDate": "20260920"
  },
  "wireguard": [ { "publicKey": "…", "latestHandshake": 1790856000 } ],
  "postfix": { "messages": 0, "oldestAgeSec": 0 },
  "knot": [ { "name": "example.org.", "role": "secondary", "serial": 2026093001, "expiresInSec": 1814000 } ]
}
```
