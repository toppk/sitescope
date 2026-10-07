---
title: Development
eyebrow: Reference
lede: Go standard library plus five dependencies, built with Nix. Here is how the code is laid out and how to work on it.
description: Building, testing and the code layout of sitescope.
---

## Build and test

```sh
nix develop          # go and gopls
go test ./...
nix build            # static binary, tests run in the sandbox
nix flake check      # the package, and the module evaluated as hub and as agent
```

The binary is built with `CGO_ENABLED=0` and `-trimpath`. Bump
`vendorHash` in `nix/package.nix` whenever `go.sum` changes; the failing
build prints the new one.

Dependencies: `filippo.io/age`, `golang.org/x/crypto` (bcrypt, terminal),
`golang.org/x/sys`, `github.com/miekg/dns` and `go.etcd.io/bbolt`.

## Versions and releases

The release number lives in `VERSION` and nowhere else. Every build reads
it and appends the git revision: the flake as `X.Y.Z+<rev>`, a plain
`go build` as `X.Y.Z+dev`. To match the flake outside Nix:

```sh
go build -ldflags "-X main.version=$(cat VERSION)+$(git rev-parse --short HEAD)" .
```

A release: bump `VERSION`, `git add -A`, `nix flake check`, check
`nix build && ./result/bin/sitescope version`, commit, push, and hand infra
the commit to pin. Tags are optional; nothing reads them.

## Layout

| path | what |
|---|---|
| `main.go` | subcommands |
| `internal/config` | the JSON configuration and its defaults |
| `internal/status` | statuses and thresholds |
| `internal/check` | expands config into checks, and every probe |
| `internal/alert` | the per-check state machine: retries, notification due |
| `internal/store` | bbolt history and states |
| `internal/hub` | scheduler, mailer, web (templates and `static/`), control socket, `hub.vault` |
| `internal/agent` | collector and its HTTP server |
| `internal/report` | the agent's report |
| `internal/vault`, `internal/secmem` | the age vault and locked memory |
| `nix/` | package, module and flake checks |
| `site/` | this documentation |

## Adding a check

1. Add its settings to `internal/config` with defaults in
   `applyDefaults`.
2. Write the probe in `internal/check` as a pure `Eval…` function plus a
   thin network wrapper, and test the `Eval…` function.
3. Register it in the builder with a stable id, an area, a group and its
   `Probes` (what `sitescope probes` lists).
4. Document it in `site/pages/checks.md`, and its traffic in
   `site/pages/probes.md`.

## This site

The documentation is Markdown in `site/pages/`, built with pandoc and the
Horizon theme in `site/theme/`:

```sh
site/build.sh _site
python3 -m http.server -d _site 8000
```

`.github/workflows/pages.yml` builds and publishes it on every push to
`master` that touches `site/`.
