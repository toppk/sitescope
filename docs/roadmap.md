# Roadmap

Planned capabilities, roughly in release order. This is a direction, not a
promise: the order changes as needs do.

## 1.3.0: modules (released)

No behaviour change; groundwork for what follows.

- Check modules: each kind of check is one file with its config section,
  defaults and checks.
- Agent collectors that skip what doesn't apply, so an agent runs on
  distributions other than NixOS.
- A notifier interface, so alerts can go somewhere other than email.
- Agents over TLS, with a CA and a token for each host on the hub.

## 1.4.0: devices and services (released)

- systemd units that must be running, and timers: last run, result, next
  run.
- Ping and TCP checks for devices, with a "seen within N hours" rule for
  devices that sleep.
- Printer supplies and state over IPP.
- HTTP options for devices: private-CA certificates, a body match, an
  expected redirect.
- An ntfy notifier, for alerts that must arrive when email can't.
- Facts for non-NixOS hosts: kernel installed vs running, and package
  update age.

## 1.5.0: a strict config (released)

- Unknown, misspelled and renamed keys fail at load, naming each one; the
  NixOS module runs the same check when the system builds.
- `sitescope config` prints the effective config.
- `"off"` instead of negative or out-of-range values; a top-level `host`
  list.
- JSON output for `check` and `probes`.

## 1.6.0: TOML (released)

- The config may be TOML, with the same keys, defaults and checks.
- Docs written in that form, with NixOS settings as one way to produce it.

## 1.7.0: FreeBSD and OpenBSD (released)

- The hub and the CLI on FreeBSD and OpenBSD, with their own vault
  hardening; release tarballs for both on x86-64. The agent stays Linux
  only.

## 1.7.1: the agent on FreeBSD and OpenBSD

- The agent and local hosts on both: disk, memory, swap, load, CPU,
  network, WireGuard, named rc services, package age; FreeBSD's reboot
  check and OpenBSD's failed rc services. Checks that differ are named
  for their system.
- Ping through the system's setuid `/sbin/ping` without root.

## 1.8.0: logs and metrics

- Kernel and journal watching: counted rules, with ignore, info-level and
  allowlist rules, so a burst of lines is one alert.
- A generic Prometheus metrics check. It also covers anything that exports
  metrics, such as Ceph's mgr module or smartctl_exporter.
- Ceph health detail through an agent with a read-only key.
- libvirt domain state.
- Push checks for jobs that report in, with a `sitescope run` wrapper.

## Later

- `sitescope discover`: list what announces itself over DNS-SD and print a
  config stub. Monitoring stays explicit.
- Alerts when a configured device stops announcing itself.
- Links between hubs, and each hub watching the other.

## Principles

- Read-only everywhere: no write keys and no actions.
- Only configured targets: no scanning or sweeping.
- Every new kind of check documents its traffic in `sitescope probes`.
- Alert volume stays bounded.
