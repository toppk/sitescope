package check

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/toppk/sitescope/internal/config"
)

type Ping struct {
	config.Timing
	Targets []PingTarget `json:"targets"`
	Loss    Threshold    `json:"loss"` // percent of echoes lost
	RTT     Threshold    `json:"rtt"`  // milliseconds, average
}

type PingTarget struct {
	Name string `json:"name"`
	Host string `json:"host"`
	// Count echoes per run, a second apart at most.
	Count int `json:"count,omitempty"`
	// Family is "4" or "6"; by default the first address, IPv4 first.
	Family     string          `json:"family,omitempty"`
	SeenWithin config.Duration `json:"seenWithin,omitempty"`
	Loss       Threshold       `json:"loss"`
	RTT        Threshold       `json:"rtt"`
	config.Timing
}

type TCP struct {
	config.Timing
	Targets []TCPTarget `json:"targets"`
}

type TCPTarget struct {
	Name       string          `json:"name"`
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	SeenWithin config.Duration `json:"seenWithin,omitempty"`
	config.Timing
}

func (p *Ping) Defaults(*config.Config) {
	p.Loss = p.Loss.Or(Threshold{Warn: 50, Crit: 100})
	for i := range p.Targets {
		t := &p.Targets[i]
		config.Def(&t.Host, t.Name)
		if t.Count == 0 {
			t.Count = 3
		}
		t.Loss, t.RTT = t.Loss.Or(p.Loss), t.RTT.Or(p.RTT)
	}
}

func (p *Ping) Validate() error {
	for _, t := range p.Targets {
		if t.Name == "" {
			return errors.New("ping: a target needs a name")
		}
		if t.Family != "" && t.Family != "4" && t.Family != "6" {
			return fmt.Errorf("ping: %s family %q, want 4 or 6", t.Name, t.Family)
		}
		if t.Count < 1 || t.Count > 20 {
			return fmt.Errorf("ping: %s count %d, want 1 to 20", t.Name, t.Count)
		}
	}
	return nil
}

func (c *TCP) Defaults(*config.Config) {
	for i := range c.Targets {
		config.Def(&c.Targets[i].Host, c.Targets[i].Name)
	}
}

func (c *TCP) Validate() error {
	for _, t := range c.Targets {
		if t.Name == "" || t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("tcp: target %q needs a name and a port", t.Name)
		}
	}
	return nil
}

func (p *Ping) build(b *builder) {
	t := p.Timing.Merge(config.Timing{Interval: config.Duration(time.Minute)})
	for _, tg := range p.Targets {
		b.add(tg.Timing.Merge(t), &Check{ID: "ping." + tg.Name, Name: "Ping " + tg.Name, Area: "devices",
			Probes: []Probe{{tg.Host, "icmp", "echo request", tg.Count}},
			Run:    seenWithin(tg.SeenWithin.D(), pingCheck(tg))})
	}
}

func (c *TCP) build(b *builder) {
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(time.Minute)})
	for _, tg := range c.Targets {
		port := strconv.Itoa(tg.Port)
		b.add(tg.Timing.Merge(t), &Check{ID: "tcp." + tg.Name, Name: "TCP " + tg.Name + ":" + port, Area: "devices",
			Probes: []Probe{{tg.Host, port + "/tcp", "connect, then close", 1}},
			Run:    seenWithin(tg.SeenWithin.D(), tcpCheck(tg.Host, port))})
	}
}

// seenWithin keeps a failing target ok while it answered within d, for devices that sleep.
func seenWithin(d time.Duration, run func(context.Context, *Env) Result) func(context.Context, *Env) Result {
	if d <= 0 {
		return run
	}
	var mu sync.Mutex
	var last, first time.Time
	return func(ctx context.Context, env *Env) Result {
		r := run(ctx, env)
		now := env.now()
		mu.Lock()
		defer mu.Unlock()
		if first.IsZero() {
			first = now
		}
		if r.Status == OK || r.Status == Warn {
			last = now
			return r
		}
		// after a hub restart the window starts again
		since, seen := last, "last seen "+fmtDuration(now.Sub(last))+" ago"
		if last.IsZero() {
			since, seen = first, "not seen since the hub started "+fmtDuration(now.Sub(first))+" ago"
		}
		if now.Sub(since) <= d {
			return Okf("asleep or away (%s); %s, within %s", r.Message, seen, fmtDuration(d))
		}
		r.Message += "; " + seen
		return r
	}
}

func tcpCheck(host, port string) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		var d net.Dialer
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return Critf("connect: %v", err)
		}
		conn.Close()
		return Okf("connected in %dms", time.Since(start).Milliseconds())
	}
}

func pingCheck(t PingTarget) func(context.Context, *Env) Result {
	return func(ctx context.Context, _ *Env) Result {
		ip, err := resolve(ctx, t.Host, t.Family)
		if err != nil {
			return Critf("%v", err)
		}
		rtts, err := Echo(ctx, ip, t.Count)
		if err != nil {
			return Unknownf("ping %s: %v", ip, err)
		}
		return EvalPing(ip.String(), t.Count, rtts, t.Loss, t.RTT)
	}
}

func EvalPing(addr string, sent int, rtts []time.Duration, loss, rtt Threshold) Result {
	if len(rtts) == 0 {
		return Critf("%s: no reply to %d echo requests", addr, sent)
	}
	lost := 100 * float64(sent-len(rtts)) / float64(sent)
	var sum time.Duration
	for _, d := range rtts {
		sum += d
	}
	avg := float64(sum.Microseconds()) / float64(len(rtts)) / 1000
	s := loss.Above(lost)
	if rtt.Warn > 0 || rtt.Crit > 0 {
		s = Worst(s, rtt.Above(avg))
	}
	return Rated(s, "%s: %d/%d replies, %.0f%% lost, rtt %.1fms", addr, len(rtts), sent, lost, avg)
}

func resolve(ctx context.Context, host, family string) (net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var v6 net.IP
	for _, a := range addrs {
		is4 := a.IP.To4() != nil
		switch {
		case is4 && family != "6":
			return a.IP, nil
		case !is4 && family != "4" && v6 == nil:
			v6 = a.IP
		}
	}
	if v6 == nil {
		return nil, fmt.Errorf("%s has no IPv%s address", host, map[string]string{"": "4 or 6", "4": "4", "6": "6"}[family])
	}
	return v6, nil
}

// Echo sends count ICMP echo requests from an unprivileged ping socket and returns the replies' round trips.
func Echo(ctx context.Context, ip net.IP, count int) ([]time.Duration, error) {
	network, laddr, proto := "udp4", "0.0.0.0", 1
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if ip.To4() == nil {
		network, laddr, proto, typ = "udp6", "::", 58, ipv6.ICMPTypeEchoRequest
	}
	conn, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (unprivileged ICMP needs net.ipv4.ping_group_range to include the hub's group)", err)
		}
		return nil, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Duration(count+2) * time.Second)
	}
	conn.SetDeadline(deadline)
	gap := min(time.Second, time.Until(deadline)/time.Duration(count+1))
	sent := make(map[int]time.Time, count)
	var rtts []time.Duration
	buf := make([]byte, 1500)
	dst := &net.UDPAddr{IP: ip}
	for seq := 1; seq <= count; seq++ {
		msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("sitescope")}}
		b, _ := msg.Marshal(nil)
		sent[seq] = time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			return nil, err
		}
		// collect replies until the next send is due; the last waits up to two seconds more
		until := time.Now().Add(gap)
		if seq == count {
			until = time.Now().Add(2 * time.Second)
		}
		if until.After(deadline) {
			until = deadline
		}
		for len(rtts) < count && time.Now().Before(until) {
			conn.SetReadDeadline(until)
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil {
				continue
			}
			if e, ok := m.Body.(*icmp.Echo); ok && (m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply) {
				if at, ok := sent[e.Seq]; ok {
					rtts = append(rtts, time.Since(at))
					delete(sent, e.Seq)
				}
			}
		}
	}
	return rtts, nil
}
