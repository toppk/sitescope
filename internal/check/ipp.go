package check

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

type IPP struct {
	config.Timing
	Targets []IPPTarget `json:"targets"`
}

type IPPTarget struct {
	Name string `json:"name"`
	// URL is the printer's ipp:// or ipps:// URI, e.g. ipp://printer.lan/ipp/print.
	URL string `json:"url"`
	// CA is a PEM file of the only CA trusted for ipps.
	CA string `json:"ca,omitempty"`
	config.Timing
}

func (c *IPP) Defaults(*config.Config) {}

func (c *IPP) Validate() error {
	for _, t := range c.Targets {
		if t.Name == "" {
			return errors.New("ipp: a target needs a name")
		}
		if _, _, err := ippURLs(t.URL); err != nil {
			return fmt.Errorf("ipp: %s: %w", t.Name, err)
		}
	}
	return nil
}

func (c *IPP) build(b *builder) {
	t := c.Timing.Merge(config.Timing{Interval: config.Duration(5 * time.Minute)})
	for _, tg := range c.Targets {
		post, _, _ := ippURLs(tg.URL)
		b.add(tg.Timing.Merge(t), &Check{ID: "ipp." + tg.Name, Name: "Printer " + tg.Name, Area: "devices",
			Probes: []Probe{urlProbe(post, "IPP Get-Printer-Attributes")},
			Run:    ippCheck(tg)})
	}
}

// ippURLs maps the printer URI to the HTTP URL to post to and the printer-uri attribute.
func ippURLs(raw string) (post, printer string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("url %q has no host", raw)
	}
	h := *u
	switch u.Scheme {
	case "ipp", "http":
		h.Scheme = "http"
	case "ipps", "https":
		h.Scheme = "https"
	default:
		return "", "", fmt.Errorf("url %q: want ipp://, ipps://, http:// or https://", raw)
	}
	if u.Port() == "" && (u.Scheme == "ipp" || u.Scheme == "ipps") {
		h.Host = u.Host + ":631"
	}
	p := h
	p.Scheme = map[string]string{"http": "ipp", "https": "ipps"}[h.Scheme]
	return h.String(), p.String(), nil
}

func ippCheck(t IPPTarget) func(context.Context, *Env) Result {
	client := caClient(t.CA)
	post, printer, _ := ippURLs(t.URL)
	return func(ctx context.Context, env *Env) Result {
		c, err := client(env)
		if err != nil {
			return Critf("CA: %v", err)
		}
		attrs, err := GetPrinterAttributes(ctx, c, post, printer)
		if err != nil {
			return Critf("%v", err)
		}
		return EvalPrinter(attrs)
	}
}

// IPP value tags, RFC 8010 section 3.5.
const (
	tagOperation = 0x01
	tagEnd       = 0x03
	tagInteger   = 0x21
	tagEnum      = 0x23
	tagKeyword   = 0x44
	tagURI       = 0x45
	tagCharset   = 0x47
	tagLanguage  = 0x48
)

var printerAttrs = []string{"printer-state", "printer-state-reasons", "marker-names", "marker-levels", "marker-low-levels", "marker-types"}

// IPPAttrs holds each attribute's values: integers and enums as int, everything else as string.
type IPPAttrs map[string][]any

func (a IPPAttrs) ints(name string) []int {
	var out []int
	for _, v := range a[name] {
		if n, ok := v.(int); ok {
			out = append(out, n)
		}
	}
	return out
}

func (a IPPAttrs) strs(name string) []string {
	var out []string
	for _, v := range a[name] {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func GetPrinterAttributes(ctx context.Context, c *http.Client, post, printer string) (IPPAttrs, error) {
	var b bytes.Buffer
	b.Write([]byte{2, 0, 0, 0x0b, 0, 0, 0, 1}) // IPP 2.0, Get-Printer-Attributes, request 1
	b.WriteByte(tagOperation)
	attr := func(tag byte, name, value string) {
		b.WriteByte(tag)
		binary.Write(&b, binary.BigEndian, uint16(len(name)))
		b.WriteString(name)
		binary.Write(&b, binary.BigEndian, uint16(len(value)))
		b.WriteString(value)
	}
	attr(tagCharset, "attributes-charset", "utf-8")
	attr(tagLanguage, "attributes-natural-language", "en")
	attr(tagURI, "printer-uri", printer)
	for i, a := range printerAttrs {
		name := ""
		if i == 0 {
			name = "requested-attributes"
		}
		attr(tagKeyword, name, a)
	}
	b.WriteByte(tagEnd)
	req, err := http.NewRequestWithContext(ctx, "POST", post, &b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseIPP(body)
}

// ParseIPP reads an IPP response's attributes, all groups together.
func ParseIPP(b []byte) (IPPAttrs, error) {
	if len(b) < 9 {
		return nil, errors.New("short IPP response")
	}
	if st := binary.BigEndian.Uint16(b[2:4]); st > 0xff {
		return nil, fmt.Errorf("IPP status 0x%04x", st)
	}
	attrs := IPPAttrs{}
	last := ""
	for i := 8; i < len(b); {
		tag := b[i]
		i++
		if tag == tagEnd {
			return attrs, nil
		}
		if tag < 0x10 {
			continue // the next group begins
		}
		if i+2 > len(b) {
			break
		}
		n := int(binary.BigEndian.Uint16(b[i:]))
		if i+2+n+2 > len(b) {
			break
		}
		name := string(b[i+2 : i+2+n])
		i += 2 + n
		vl := int(binary.BigEndian.Uint16(b[i:]))
		if i+2+vl > len(b) {
			break
		}
		v := b[i+2 : i+2+vl]
		i += 2 + vl
		if name == "" {
			name = last // an additional value of the previous attribute
		}
		last = name
		switch {
		case (tag == tagInteger || tag == tagEnum) && len(v) == 4:
			attrs[name] = append(attrs[name], int(int32(binary.BigEndian.Uint32(v))))
		case tag >= 0x40:
			attrs[name] = append(attrs[name], string(v))
		}
	}
	return nil, errors.New("truncated IPP response")
}

// critReasons stop the printer until someone acts, whatever their suffix.
var critReasons = []string{"jam", "door-open", "cover-open", "marker-supply-empty", "toner-empty"}

func EvalPrinter(a IPPAttrs) Result {
	s := OK
	var parts []string
	state := map[int]string{3: "idle", 4: "printing", 5: "stopped"}
	if st := a.ints("printer-state"); len(st) > 0 {
		name := state[st[0]]
		if name == "" {
			name = fmt.Sprintf("state %d", st[0])
		}
		if st[0] == 5 {
			s = Warn
		}
		parts = append(parts, name)
	}
	names, levels, lows := a.strs("marker-names"), a.ints("marker-levels"), a.ints("marker-low-levels")
	var supplies []string
	for i, lvl := range levels {
		name := fmt.Sprintf("supply %d", i+1)
		if i < len(names) {
			name = names[i]
		}
		low := 10
		if i < len(lows) && lows[i] > 0 {
			low = lows[i]
		}
		switch {
		case lvl == -3:
			supplies = append(supplies, name+" ok")
		case lvl < 0:
			supplies = append(supplies, name+" unknown")
		case lvl == 0:
			s = Worst(s, Crit)
			supplies = append(supplies, name+" empty")
		case lvl <= low:
			s = Worst(s, Warn)
			supplies = append(supplies, fmt.Sprintf("%s %d%% (low)", name, lvl))
		default:
			supplies = append(supplies, fmt.Sprintf("%s %d%%", name, lvl))
		}
	}
	if len(supplies) > 0 {
		parts = append(parts, strings.Join(supplies, ", "))
	}
	var reasons []string
	for _, r := range a.strs("printer-state-reasons") {
		// cups- reasons are a print server's notes, not the printer's
		if r == "none" || strings.HasSuffix(r, "-report") || strings.HasPrefix(r, "cups-") {
			continue
		}
		reasons = append(reasons, r)
		switch {
		case strings.HasSuffix(r, "-error") || containsAny(r, critReasons):
			s = Worst(s, Crit)
		case strings.HasSuffix(r, "-warning"):
			s = Worst(s, Warn)
		}
	}
	if len(reasons) > 0 {
		parts = append(parts, strings.Join(reasons, ", "))
	}
	if len(parts) == 0 {
		return Unknownf("the printer reported no state or supplies")
	}
	return Rated(s, "%s", strings.Join(parts, "; "))
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
