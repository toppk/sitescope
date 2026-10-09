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

CI (`.github/workflows/ci.yml`) runs on every push and pull request: the
tests, a plain `go build` and a Nix build that must both report
`VERSION+rev`, `nix flake check`, and a check that the Nix binary is
statically linked.

### Compatibility

During a rolling update a new hub reads old agents' reports and the
reverse, and `sitescope verify` and other hubs read `/healthz` and
`/status.json` from any recent release. So fields in the agent report and
`/status.json` are only added, never renamed, removed or retyped, and new
report fields are optional to the hub. `testdata/compat/` holds each
format as of 1.3.0. `TestReportCompat` and `TestStatusCompat` fail when a field
is removed, renamed or retyped, and `TestAgentReportCompat` runs the hub's checks
on the old report. When either protocol changes on purpose, add a fixture
for the new release and a test for what the old side does with it.

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

A release: bump `VERSION`, write `release-notes/X.Y.Z.md` from
`release-notes/TEMPLATE.md`, `git add -A`, `nix flake check`, check
`nix build && ./result/bin/sitescope version`, commit, push, and hand infra
the commit to pin. Tags are optional; nothing reads them.

## Layout

| path | what |
|---|---|
| `main.go` | subcommands |
| `internal/config` | the JSON configuration: hub, agent, alerts, public, and the section registry |
| `internal/status` | statuses and thresholds |
| `internal/check` | the check modules: each section's settings, defaults, checks and probes |
| `internal/alert` | the per-check state machine: retries, notification due |
| `internal/store` | bbolt history and states |
| `internal/hub` | scheduler, notifiers (email), web (templates and `static/`), control socket, `hub.vault` |
| `internal/agent` | collector and its HTTP server |
| `internal/report` | the agent's report |
| `internal/vault`, `internal/secmem` | the age vault and locked memory |
| `nix/` | package, module and flake checks |
| `site/` | this documentation |

## Adding a check

Each kind of check is a module in `internal/check`: one file holds its
config section type, and that type has three methods.

- `Defaults(*config.Config)` fills in defaults. It may read the hub settings
  and other sections.
- `Validate()` rejects bad settings.
- `build(*builder)` adds checks.

To add one:

1. Write the section type and its methods, and register its top-level key
   in the `init` in `build.go`. Registration order is build order.
2. Write the probe as a pure `Eval…` function plus a thin network wrapper,
   and test the `Eval…` function.
3. Give each check a stable id, an area, a group and its `Probes` (what
   `sitescope probes` lists). Other code reads a section with
   `config.Get[*check.T](cfg)`.
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
