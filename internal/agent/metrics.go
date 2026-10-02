package agent

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/report"
)

// promWriter emits Prometheus text format 0.0.4, one HELP/TYPE header per family.
type promWriter struct {
	w    io.Writer
	seen map[string]bool
}

func (p *promWriter) family(name, typ, help string) {
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// sample writes one value; labels alternate name, value.
func (p *promWriter) sample(name string, v float64, labels ...string) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i] + `="` + escapeLabel(labels[i+1]) + `"`)
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(p.w, "%s %s\n", b.String(), strconv.FormatFloat(v, 'g', -1, 64))
}

func (p *promWriter) one(name, typ, help string, v float64, labels ...string) {
	p.family(name, typ, help)
	p.sample(name, v, labels...)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }

// WriteMetrics renders a report with node_exporter's names where they overlap, sitescope_ otherwise.
func WriteMetrics(w io.Writer, r *report.Report, peers map[string]string, errs map[string]uint64, version string, now time.Time) {
	p := &promWriter{w: w, seen: map[string]bool{}}
	const counter, gauge, untyped = "counter", "gauge", "untyped"

	if k := r.Counters; k != nil {
		p.family("node_cpu_seconds_total", counter, "Seconds the CPUs spent in each mode.")
		for i, c := range k.CPU {
			cpu := strconv.Itoa(i)
			for _, m := range []struct {
				mode string
				v    float64
			}{{"user", c.User}, {"nice", c.Nice}, {"system", c.System}, {"idle", c.Idle},
				{"iowait", c.IOWait}, {"irq", c.IRQ}, {"softirq", c.SoftIRQ}, {"steal", c.Steal}} {
				p.sample("node_cpu_seconds_total", m.v, "cpu", cpu, "mode", m.mode)
			}
		}
		for _, res := range []string{"cpu", "memory", "io"} {
			ps, ok := k.Pressure[res]
			if !ok {
				continue
			}
			p.one("node_pressure_"+res+"_waiting_seconds_total", counter,
				"Total time in seconds that processes have waited for "+res+".", float64(ps.SomeTotalUS)/1e6)
			if res != "cpu" {
				p.one("node_pressure_"+res+"_stalled_seconds_total", counter,
					"Total time in seconds no process could make progress due to "+res+".", float64(ps.FullTotalUS)/1e6)
			}
		}
		p.one("node_vmstat_oom_kill", untyped, "/proc/vmstat information field oom_kill.", float64(k.VM.OOMKill))
		p.one("node_vmstat_pswpin", untyped, "/proc/vmstat information field pswpin.", float64(k.VM.PswpIn))
		p.one("node_vmstat_pswpout", untyped, "/proc/vmstat information field pswpout.", float64(k.VM.PswpOut))
		p.one("node_vmstat_pgmajfault", untyped, "/proc/vmstat information field pgmajfault.", float64(k.VM.PgMajFault))
		for _, d := range k.Disks {
			p.one("node_disk_reads_completed_total", counter, "The total number of reads completed successfully.", float64(d.Reads), "device", d.Device)
		}
		for _, d := range k.Disks {
			p.one("node_disk_writes_completed_total", counter, "The total number of writes completed successfully.", float64(d.Writes), "device", d.Device)
		}
		for _, d := range k.Disks {
			p.one("node_disk_read_bytes_total", counter, "The total number of bytes read successfully.", float64(d.ReadBytes), "device", d.Device)
		}
		for _, d := range k.Disks {
			p.one("node_disk_written_bytes_total", counter, "The total number of bytes written successfully.", float64(d.WrittenBytes), "device", d.Device)
		}
		for _, d := range k.Disks {
			p.one("node_disk_io_time_seconds_total", counter, "Total seconds spent doing I/Os.", float64(d.IOTimeMS)/1000, "device", d.Device)
		}
		netFields := []struct {
			name, help string
			v          func(report.NetIO) uint64
		}{
			{"node_network_receive_bytes_total", "Network device statistic receive_bytes.", func(n report.NetIO) uint64 { return n.RxBytes }},
			{"node_network_transmit_bytes_total", "Network device statistic transmit_bytes.", func(n report.NetIO) uint64 { return n.TxBytes }},
			{"node_network_receive_errs_total", "Network device statistic receive_errs.", func(n report.NetIO) uint64 { return n.RxErrs }},
			{"node_network_transmit_errs_total", "Network device statistic transmit_errs.", func(n report.NetIO) uint64 { return n.TxErrs }},
			{"node_network_receive_drop_total", "Network device statistic receive_drop.", func(n report.NetIO) uint64 { return n.RxDrop }},
			{"node_network_transmit_drop_total", "Network device statistic transmit_drop.", func(n report.NetIO) uint64 { return n.TxDrop }},
		}
		for _, f := range netFields {
			for _, n := range k.Net {
				p.one(f.name, counter, f.help, float64(f.v(n)), "device", n.Device)
			}
		}
		if k.BootTime > 0 {
			p.one("node_boot_time_seconds", gauge, "Node boot time, in unixtime.", float64(k.BootTime))
		}
	}
	p.one("node_time_seconds", gauge, "System time in seconds since epoch (1970).", float64(now.UnixNano())/1e9)
	p.one("node_load1", gauge, "1m load average.", r.Load[0])
	p.one("node_load5", gauge, "5m load average.", r.Load[1])
	p.one("node_load15", gauge, "15m load average.", r.Load[2])

	m := r.Memory
	if m.TotalKB > 0 {
		for _, f := range []struct {
			name string
			kb   uint64
		}{{"MemTotal", m.TotalKB}, {"MemAvailable", m.AvailableKB}, {"MemFree", m.FreeKB}, {"Buffers", m.BuffersKB},
			{"Cached", m.CachedKB}, {"Shmem", m.ShmemKB}, {"Dirty", m.DirtyKB}, {"SwapTotal", m.SwapTotalKB}, {"SwapFree", m.SwapFreeKB}} {
			name := "node_memory_" + f.name + "_bytes"
			p.one(name, gauge, "Memory information field "+f.name+"_bytes.", float64(f.kb*1024))
		}
	}

	fsFields := []struct {
		name, help string
		v          func(report.Disk) uint64
	}{
		{"node_filesystem_size_bytes", "Filesystem size in bytes.", func(d report.Disk) uint64 { return d.TotalBytes }},
		{"node_filesystem_avail_bytes", "Filesystem space available to non-root users in bytes.", func(d report.Disk) uint64 { return d.AvailBytes }},
		{"node_filesystem_files", "Filesystem total file nodes.", func(d report.Disk) uint64 { return d.Files }},
		{"node_filesystem_files_free", "Filesystem total free file nodes.", func(d report.Disk) uint64 { return d.FilesFree }},
	}
	for _, f := range fsFields {
		for _, d := range r.Disks {
			p.one(f.name, gauge, f.help, float64(f.v(d)), "device", d.Device, "fstype", d.FSType, "mountpoint", d.Mount)
		}
	}

	if r.FailedUnits != nil {
		p.one("sitescope_systemd_units_failed", gauge, "Number of systemd units in the failed state.", float64(len(r.FailedUnits)))
	}
	for _, u := range r.Units {
		p.one("sitescope_systemd_unit_memory_bytes", gauge, "Memory used by the unit's cgroup.", float64(u.Bytes), "unit", u.Unit)
	}
	for _, u := range r.Units {
		if u.MaxBytes > 0 {
			p.one("sitescope_systemd_unit_memory_max_bytes", gauge, "The unit's MemoryMax.", float64(u.MaxBytes), "unit", u.Unit)
		}
	}

	if q := r.Postfix; q != nil {
		p.family("sitescope_postfix_queue_messages", gauge, "Messages in the postfix queue, by queue.")
		for _, name := range sortedKeys(q.Queues) {
			p.sample("sitescope_postfix_queue_messages", float64(q.Queues[name]), "queue", name)
		}
		p.one("sitescope_postfix_queue_oldest_seconds", gauge, "Age of the oldest queued message.", q.OldestAgeSec)
	}
	if r.Knot != nil {
		p.one("sitescope_knot_zones", gauge, "Zones loaded in Knot.", float64(len(r.Knot)))
		for _, z := range r.Knot {
			p.one("sitescope_knot_zone_serial", gauge, "SOA serial of the zone.", float64(z.Serial), "zone", z.Name)
		}
		for _, z := range r.Knot {
			if z.ExpiresInSec >= 0 {
				p.one("sitescope_knot_zone_expires_seconds", gauge, "Seconds until a secondary zone expires.", float64(z.ExpiresInSec), "zone", z.Name)
			}
		}
	}
	names := peerNames(r.WireGuard, peers)
	for i, w := range r.WireGuard {
		p.one("sitescope_wireguard_latest_handshake_seconds", gauge, "Unix time of the peer's latest handshake; 0 means never.", float64(w.LatestHandshake), "peer", names[i])
	}
	for i, w := range r.WireGuard {
		p.one("sitescope_wireguard_received_bytes_total", counter, "Bytes received from the peer.", float64(w.RxBytes), "peer", names[i])
	}
	for i, w := range r.WireGuard {
		p.one("sitescope_wireguard_sent_bytes_total", counter, "Bytes sent to the peer.", float64(w.TxBytes), "peer", names[i])
	}

	if r.System.Current != "" {
		b := 0.0
		if r.System.RebootNeeded {
			b = 1
		}
		p.one("sitescope_reboot_required", gauge, "1 when the kernel, initrd or modules changed since boot.", b)
	}
	if d, err := time.Parse("20060102", r.System.NixpkgsDate); err == nil {
		p.one("sitescope_nixpkgs_age_seconds", gauge, "Age of the running system's nixpkgs revision.", now.Sub(d).Seconds())
	}
	p.one("sitescope_agent_build_info", gauge, "A metric with constant value 1, labelled by version.", 1, "version", version)
	p.family("sitescope_agent_collect_errors_total", counter, "Collection failures since the agent started, by collector.")
	for _, c := range sortedKeys(errs) {
		p.sample("sitescope_agent_collect_errors_total", float64(errs[c]), "collector", c)
	}
}

// peerNames labels peers by inventory name, never by key; unknown peers get a stable index.
func peerNames(ws []report.WGPeer, names map[string]string) []string {
	out := make([]string, len(ws))
	unknown := 0
	for i, w := range ws {
		if n := names[w.PublicKey]; n != "" {
			out[i] = n
		} else {
			unknown++
			out[i] = fmt.Sprintf("unnamed%d", unknown)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
