# Roadmap

Planned capabilities, roughly in release order. This is a direction, not a
promise: the order changes as needs do.

## 1.3.0: modules

No behaviour change; groundwork for what follows.

- Check modules: each kind of check is one file with its config section,
  defaults and checks.
- Agent collectors that skip what doesn't apply, so an agent runs on
  distributions other than NixOS.
- A notifier interface, so alerts can go somewhere other than email.
- Agents over TLS, with a CA and a token for each host on the hub.

## 1.4.0: devices and services

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

## 1.5.0: logs and metrics

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
