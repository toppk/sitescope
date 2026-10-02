---
title: Security model
eyebrow: Reference
lede: What sitescope protects, from whom, and how. A monitor sees everything, so it is built to be uninteresting to break into.
description: The threat model behind sitescope's vault, process hardening, public page and read-only tokens.
---

## What it holds

- **Read-only API tokens** for the cloud provider and DNS host. Billing
  and record contents, nothing that can change infrastructure.
- **The agent token**, which reads host facts over WireGuard only.
- **A picture of the infrastructure**: hosts, addresses, versions, what
  is failing. Useful to an attacker, so it isn't public.

## Rules it follows

::: safety
**Nothing it does changes the infrastructure.** Tokens are scoped read
only, probes only ask, and the open-relay probe stops at `RCPT TO`.
:::

- **Plaintext secrets never touch the disk.** The vault is decrypted into
  locked memory; edits are encrypted before they are written.
- **Secrets are never logged** and never appear in error messages.
- **No unlock from the web.** Only a member of the admin group, on the
  hub host, through a mode 0660 socket.
- **Secrets from outside the store.** The environment file is not in
  `/nix/store`, where every user could read it.
- **The public page says only what you allow.** Each check is public
  under a label, grouped into a service light, or private. Checks no rule
  matches are public under their own names, so add a catch-all private
  rule if names like hostnames must not show. Messages are never public.

## Process hardening

| measure | effect |
|---|---|
| `mlock` + `MADV_DONTDUMP` on the vault buffer | secrets aren't swapped out or written to crash dumps |
| `PR_SET_DUMPABLE=0` | no ptrace or `/proc/PID/mem` from same-user processes |
| `LimitCORE=0`, `RLIMIT_CORE=0` | no core files |
| buffers zeroed on lock, SIGTERM and exit | a locked hub holds no plaintext |
| separate users for hub and agent | the vault process has no capabilities |
| systemd sandboxing | see [NixOS module](nixos.html) |

## Authentication

- **Agents** compare the bearer token in constant time.
- **The detail view** uses basic auth against a bcrypt (cost 12) hash
  stored in the vault, so a locked hub can't authenticate anyone. Failures
  are limited to one per second.
- **The control socket** checks the caller with `SO_PEERCRED` and logs it.

## Known limits

- A token is copied to the Go heap while it is placed in an HTTP header,
  and age decrypts through a heap buffer. Neither is zeroed.
- Basic auth relies on the reverse proxy's TLS.
- Anyone with root on the hub host can read its memory.
