# Deploying sitescope

Deployment requirements, as a checklist for the infrastructure repo. Two units:

- `sitescope` (hub, one host)
- `sitescope-agent` (every NixOS host, the hub host included via `agent.enable`)

```yaml
app: sitescope
hostname: status.example.org
repo: github:toppk/sitescope
listen_port: 8470            # hub, on 127.0.0.1
health_path: /healthz
websockets: no
max_request_body: 0          # GET only
state:
  path: /var/lib/sitescope   # history.db (bbolt) + vault.age
  size_estimate: 20          # MB; ~100 checks x 35 days, bounded by retentionDays
  backup: yes                # vault.age matters (else re-enter tokens); history is optional
secrets:                     # environmentFile, KEY=value, outside the store
  - SITESCOPE_AGENT_TOKEN    # hub + every agent, same value
  - SITESCOPE_HEARTBEAT_URL  # hub only
outbound_network:
  - agents over wg0: 10.0.0.{1,2,3}:9105/tcp
  - the hidden primary 10.0.0.1:53 (SOA)
  - the secondaries' public IPs :53 udp+tcp, :25, :443 (v4 and v6)
  - 1.1.1.1:53 (public resolver for delegation/resolution checks)
  - 127.0.0.1:53 (local unbound, DNS blocklists)
  - 127.0.0.1:25 (alert mail)
  - TLD name servers :53, RDAP servers :443 (data.iana.org, rdap.nic.us, rdap.registry.co, ...)
  - api.linode.com:443, api.cloudflare.com:443, api.certspotter.com:443
  - the heartbeat URL host :443
  - every http/tls target :443
memory_estimate: 20          # MB hub RSS (measured 19 MB with 70 checks); MemoryMax 64M covers the 32 MiB scrypt spike at unlock
scheduled_jobs: none         # all scheduling is internal (open-relay probe and CT daily, RDAP 12h, digest daily)
other_hostnames: none
```

## Agent

```yaml
listen: <wg0 address>:9105   # bound with IP_FREEBIND, so it may start before wg0 is up
auth: Authorization: Bearer $SITESCOPE_AGENT_TOKEN
firewall: open 9105/tcp on wg0 only
memory_estimate: 12          # MB RSS; MemoryMax 32M
privileges: CAP_NET_ADMIN (ambient, for `wg show`), groups postdrop and knot when those services are enabled
```

## Vault secrets

| name | minimum scope |
|---|---|
| `linode_token` | Linode PAT: Account Read Only, Events Read Only, Linodes Read Only |
| `cloudflare_token` | Cloudflare token: Zone / DNS / Read on the one zone (Zone / Zone / Read only if `cloudflare.zoneId` is unset). To watch other tokens add User → API Tokens → Read (Account → Account API Tokens → Read for account-owned tokens); it shows names and expiry, never token values |
| `certspotter_token` | optional Cert Spotter API key (raises the CT rate limit) |
| `admin_password_hash` | set with `sitescope vault set-password` |

## Wiring

```nix
inputs.sitescope.url = "github:toppk/sitescope";
inputs.sitescope.inputs.nixpkgs.follows = "nixpkgs";

# the hub host
imports = [ inputs.sitescope.nixosModules.default ];
services.sitescope = {
  enable = true;
  role = "hub";
  agent = { enable = true; listenAddress = "10.0.0.2"; };
  environmentFile = "/var/lib/sitescope-secrets/sitescope.env";
  settings = import ../sitescope-settings.nix { inherit lib; };   # see README.md
};
users.users.alice.extraGroups = [ "sitescope-admin" ];
# reverse proxy: status.example.org -> 127.0.0.1:8470
networking.firewall.interfaces.wg0.allowedTCPPorts = [ 9105 ];

# every other host
services.sitescope = {
  enable = true;
  role = "agent";
  listenAddress = "10.0.0.X";
  environmentFile = "/var/lib/sitescope-secrets/sitescope.env";
};
```

After the first deploy: `sudo -u sitescope sitescope vault set linode_token`,
`... cloudflare_token`, `... vault set-password`, then `sitescope unlock`.
After every hub restart, run `sitescope unlock` again. The startup email is
the reminder, and `hub.vault` warns 15 minutes later if it is still locked.
