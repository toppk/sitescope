---
title: Vault and secrets
eyebrow: Use
lede: API tokens live in an age-encrypted file and are only ever decrypted into locked memory, by an operator, after the hub starts.
description: How the sitescope vault stores, unlocks and protects API tokens, and the minimum token scopes.
---

## What goes where

| secret | where | why |
|---|---|---|
| agent token | `environmentFile` | agents need it unattended, and it only reads host facts |
| heartbeat URL | `environmentFile` | the hub needs it from startup |
| Linode token | vault | reads billing and account details |
| Cloudflare token | vault | reads DNS records |
| admin password hash | vault | protects the detail view |

## The file

`/var/lib/sitescope/vault.age` is encrypted with
[age](https://age-encryption.org) in passphrase mode. scrypt uses work
factor 2^15, which needs 32 MiB during unlock; age's default of 2^18 would
need 256 MiB, four times the hub's memory limit. Writes go to a temporary
file with mode 0600, are synced, and then renamed over the old one. The
plaintext never touches the disk. The vault holds at most 64 KiB.

Back it up. Without it you re-enter the tokens; history is optional.

## Unlocking

The hub always starts locked, and says so by email. Until it is unlocked,
checks that need a secret report `locked` (which doesn't count against any
light), and the detail view answers 503. Everything else runs.

```sh
sitescope unlock      # passphrase from the terminal, over the control socket
sitescope lock
```

The control socket is mode 0660, owned by the admin group, and the hub logs
each caller's uid and pid. There is no way to unlock from the web.

After `vault set`, the running hub keeps the old contents until the next
`sitescope unlock`.

## In memory

- The decrypted vault lives in one buffer allocated with `mmap`, outside
  the Go heap, `mlock`ed (never swapped) and marked `MADV_DONTDUMP`.
- It is zeroed and unmapped on `lock`, on SIGTERM and on exit.
- The process is not dumpable (`PR_SET_DUMPABLE=0`) and has no core
  limit, so other processes of the same user can't read its memory.
- Secrets are never logged, and never part of an error.

::: warning
Two copies are unavoidable: a token sits on the Go heap for the moment it
is put in an `Authorization` header, and age decrypts through its own heap
buffer. Both are short-lived, but not zeroed.
:::

## Token scopes

Give each token the least it needs.

| name | minimum scope |
|---|---|
| `linode_token` | Personal access token with Account: Read Only, Events: Read Only, Linodes: Read Only; everything else No Access |
| `cloudflare_token` | Zone → DNS → Read, for the one zone. Add Zone → Zone → Read only if `cloudflare.zoneId` is not set. To watch other tokens add User → API Tokens → Read (Account → Account API Tokens → Read for account-owned tokens); it shows names and expiry, never token values |

The secret names can be changed with `linode.tokenSecret` and
`cloudflare.tokenSecret`.
