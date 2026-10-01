---
title: Agent report
eyebrow: Reference
lede: The one document an agent serves. Plain JSON, so anything else that can reach wg0 and holds the token can read it too.
description: The JSON schema of the sitescope agent's /v1/report endpoint.
---

## Endpoint

```sh
curl -H "Authorization: Bearer $SITESCOPE_AGENT_TOKEN" http://10.0.0.3:9105/v1/report
```

`GET /v1/report` returns the report, collected at most every 10 seconds
and cached in between. `GET /healthz` answers 200 without a token.

## Fields

| field | type | |
|---|---|---|
| `host` | string | hostname |
| `time` | RFC 3339 | when it was collected |
| `uptimeSec` | number | |
| `load` | [3]number | 1, 5 and 15 minute load |
| `cpus` | int | |
| `memory` | object | `totalKB`, `availableKB`, `swapTotalKB`, `swapFreeKB` |
| `disks` | array | `mount`, `fsType`, `totalBytes`, `availBytes`, `usedPct`, `inodesPct`; real filesystems only, one per device |
| `failedUnits` | []string | from `systemctl list-units --state=failed` |
| `system` | object | `booted`, `current` (store paths), `rebootNeeded`, `nixosVersion`, `nixpkgsDate` (`YYYYMMDD`) |
| `wireguard` | array | `publicKey`, `latestHandshake` (Unix seconds, 0 = never) |
| `postfix` | object | `messages`, `oldestAgeSec`; only when enabled |
| `knot` | array | `name`, `role`, `serial`, `expiresInSec` (-1 when not a secondary); only when enabled |
| `errors` | object | section name → error, for each section that couldn't be collected |

A failure in one section leaves the rest of the report intact.

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
