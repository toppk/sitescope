package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// fromTOML turns a TOML config into the JSON document the loader checks, each table's keys in document order.
func fromTOML(b []byte) ([]byte, error) {
	var v map[string]any
	md, err := toml.Decode(string(b), &v)
	if err != nil {
		return nil, err
	}
	order := map[string]int{}
	for i, k := range md.Keys() {
		if _, ok := order[k.String()]; !ok {
			order[k.String()] = i
		}
	}
	var out bytes.Buffer
	if err := tomlValue(&out, v, nil, order); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func tomlValue(w *bytes.Buffer, v any, path toml.Key, order map[string]int) error {
	switch x := v.(type) {
	case map[string]any:
		keys := slices.Collect(func(yield func(string) bool) {
			for k := range x {
				if !yield(k) {
					return
				}
			}
		})
		at := func(k string) int { return order[append(slices.Clone(path), k).String()] }
		slices.SortFunc(keys, func(a, b string) int { return at(a) - at(b) })
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			kj, _ := json.Marshal(k)
			w.Write(kj)
			w.WriteByte(':')
			if err := tomlValue(w, x[k], append(slices.Clone(path), k), order); err != nil {
				return err
			}
		}
		w.WriteByte('}')
	case []map[string]any:
		return tomlValue(w, toAny(x), path, order)
	case []any:
		w.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := tomlValue(w, e, path, order); err != nil {
				return err
			}
		}
		w.WriteByte(']')
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("%s: nan and inf aren't allowed", path)
		}
		j, _ := json.Marshal(x)
		w.Write(j)
	case string, int64, bool:
		j, _ := json.Marshal(x)
		w.Write(j)
	default:
		return fmt.Errorf("%s: dates and times aren't used in a sitescope config; write a string", path)
	}
	return nil
}

func toAny(x []map[string]any) []any {
	out := make([]any, len(x))
	for i, m := range x {
		out[i] = m
	}
	return out
}

// node is a JSON value with object keys in order, for writing TOML.
type node struct {
	keys  []string
	obj   map[string]*node
	arr   []*node
	raw   json.RawMessage // a scalar
	isObj bool
	isArr bool
}

func readNode(dec *json.Decoder) (*node, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		n := &node{isObj: true, obj: map[string]*node{}}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			c, err := readNode(dec)
			if err != nil {
				return nil, err
			}
			n.keys = append(n.keys, k.(string))
			n.obj[k.(string)] = c
		}
		_, err := dec.Token()
		return n, err
	case json.Delim('['):
		n := &node{isArr: true}
		for dec.More() {
			c, err := readNode(dec)
			if err != nil {
				return nil, err
			}
			n.arr = append(n.arr, c)
		}
		_, err := dec.Token()
		return n, err
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if n, ok := t.(json.Number); ok {
		return &node{raw: json.RawMessage(n)}, nil
	}
	if err := e.Encode(t); err != nil {
		return nil, err
	}
	return &node{raw: bytes.TrimSpace(b.Bytes())}, nil
}

func (n *node) null() bool { return n.raw != nil && string(n.raw) == "null" }

// small objects, with at most four keys and nothing nested but lists of scalars, fit on one line.
func (n *node) small() bool {
	if !n.isObj || len(n.keys) > 4 {
		return false
	}
	for _, k := range n.keys {
		if c := n.obj[k]; c.isObj || c.isArr && len(c.arr) > 0 && (c.arr[0].isObj || c.arr[0].isArr) {
			return false
		}
	}
	return len(inline(n)) <= 80
}

// table reports whether n is written as a table: an object at the top level, an object that isn't small, or a list of them.
func (n *node) table(top bool) bool {
	if n.isArr {
		for _, e := range n.arr {
			if e.isObj && !e.small() {
				return true
			}
		}
		return false
	}
	return n.isObj && (top || !n.small())
}

// WriteTOML writes a JSON config document as TOML; null values are left out.
func WriteTOML(w io.Writer, doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	root, err := readNode(dec)
	if err != nil {
		return err
	}
	if !root.isObj {
		return errors.New("toml: want an object")
	}
	var b strings.Builder
	writeTable(&b, root, nil, false)
	_, err = io.WriteString(w, strings.TrimLeft(b.String(), "\n"))
	return err
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func tomlKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	j, _ := json.Marshal(k)
	return string(j)
}

func tomlPath(p []string) string {
	q := make([]string, len(p))
	for i, k := range p {
		q[i] = tomlKey(k)
	}
	return strings.Join(q, ".")
}

func inline(n *node) string {
	switch {
	case n.isObj:
		var parts []string
		for _, k := range n.keys {
			if c := n.obj[k]; !c.null() {
				parts = append(parts, tomlKey(k)+" = "+inline(c))
			}
		}
		if len(parts) == 0 {
			return "{}"
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	case n.isArr:
		var parts []string
		for _, c := range n.arr {
			parts = append(parts, inline(c))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return string(n.raw)
}

// writeTable writes n's inline keys, then its tables; a header is written when n has keys of its own, or nothing at all.
func writeTable(b *strings.Builder, n *node, path []string, header bool) {
	var own, tables []string
	for _, k := range n.keys {
		switch c := n.obj[k]; {
		case c.null():
		case c.table(path == nil):
			tables = append(tables, k)
		default:
			own = append(own, k)
		}
	}
	if header && (len(own) > 0 || len(tables) == 0) {
		fmt.Fprintf(b, "\n[%s]\n", tomlPath(path))
	}
	for _, k := range own {
		c := n.obj[k]
		if c.isArr && len(c.arr) > 0 && c.arr[0].isObj {
			fmt.Fprintf(b, "%s = [\n", tomlKey(k))
			for _, e := range c.arr {
				fmt.Fprintf(b, "  %s,\n", inline(e))
			}
			b.WriteString("]\n")
			continue
		}
		fmt.Fprintf(b, "%s = %s\n", tomlKey(k), inline(c))
	}
	for _, k := range tables {
		c, p := n.obj[k], append(slices.Clone(path), k)
		if c.isArr {
			for _, e := range c.arr {
				fmt.Fprintf(b, "\n[[%s]]\n", tomlPath(p))
				writeTable(b, e, p, false)
			}
			continue
		}
		writeTable(b, c, p, true)
	}
}
