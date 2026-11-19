package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// renamed are key paths of earlier releases (list indices dropped); the old form fails to load.
var renamed = map[string]string{
	"hosts.hosts": "host",
}

type field struct {
	name  string
	index []int
	typ   reflect.Type
	off   bool
}

// fields lists t's JSON keys, with embedded structs' keys promoted as encoding/json does.
func fields(t reflect.Type) []field {
	var out []field
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" || !f.IsExported() && !f.Anonymous {
			continue
		}
		if f.Anonymous && tag == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for _, ef := range fields(et) {
					ef.index = append([]int{i}, ef.index...)
					out = append(out, ef)
				}
				continue
			}
		}
		if tag == "" {
			tag = f.Name
		}
		out = append(out, field{tag, []int{i}, f.Type, f.Tag.Get("config") == "off"})
	}
	return out
}

func coreFields() []field { return fields(reflect.TypeFor[Config]()) }

type keyCheck struct{ errs []string }

func (k *keyCheck) fail(path, f string, a ...any) {
	k.errs = append(k.errs, path+": "+fmt.Sprintf(f, a...))
}

// checkKeys reports every unknown, renamed or mistyped key in a config document, with its path.
func checkKeys(b []byte) error {
	k := &keyCheck{}
	keys, vals, err := object(b)
	if err != nil {
		return err
	}
	top := map[string]field{}
	for _, f := range coreFields() {
		top[f.name] = f
	}
	for _, r := range registry {
		t := reflect.TypeOf(r.new())
		top[r.key] = field{name: r.key, typ: t}
		for _, l := range r.lists {
			top[l] = field{name: l, typ: reflect.TypeOf(r.new().(Lists).List(l))}
		}
	}
	for _, key := range keys {
		f, ok := top[key]
		switch {
		case !ok:
			k.unknown(key, "", key, top)
		case string(vals[key]) == "null":
			k.fail(key, "null; leave the key out to turn %s off", key)
		default:
			k.value(key, key, vals[key], f.typ, f.off)
		}
	}
	switch len(k.errs) {
	case 0:
		return nil
	case 1:
		return errors.New(k.errs[0])
	}
	return fmt.Errorf("%d problems:\n  %s", len(k.errs), strings.Join(k.errs, "\n  "))
}

func (k *keyCheck) unknown(path, generic, key string, known map[string]field) {
	old := key
	if generic != "" {
		old = generic + "." + key
	}
	if to, ok := renamed[old]; ok {
		k.fail(path, "renamed in 1.5.0: use %s", to)
		return
	}
	names := slices.Sorted(maps.Keys(known))
	if s := suggest(key, names); s != "" {
		k.fail(path, "unknown key (did you mean %s?)", s)
		return
	}
	k.fail(path, "unknown key")
}

var (
	durationType  = reflect.TypeFor[Duration]()
	rawType       = reflect.TypeFor[json.RawMessage]()
	unmarshalType = reflect.TypeFor[json.Unmarshaler]()
)

// value checks raw against t; generic is the path without list indices or map keys, for renamed.
func (k *keyCheck) value(path, generic string, raw json.RawMessage, t reflect.Type, off bool) {
	if string(raw) == "null" {
		return // unset, as if the key were absent
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	first := raw[0]
	switch {
	case t == durationType:
		k.duration(path, raw, off)
		return
	case t == rawType || t.Kind() == reflect.Interface:
		return
	case t.Kind() != reflect.Struct && reflect.PointerTo(t).Implements(unmarshalType):
		if err := json.Unmarshal(raw, reflect.New(t).Interface()); err != nil {
			k.fail(path, "%v", err)
		}
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if first != '{' {
			k.fail(path, "want an object")
			return
		}
		keys, vals, err := object(raw)
		if err != nil {
			k.fail(path, "%v", err)
			return
		}
		known := map[string]field{}
		for _, f := range fields(t) {
			known[f.name] = f
		}
		for _, key := range keys {
			f, ok := known[key]
			if !ok {
				k.unknown(path+"."+key, generic, key, known)
				continue
			}
			k.value(path+"."+key, generic+"."+key, vals[key], f.typ, f.off)
		}
	case reflect.Slice, reflect.Array:
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) != nil {
			k.fail(path, "want a list")
			return
		}
		for i, e := range elems {
			k.value(path+"["+strconv.Itoa(i)+"]", generic, e, t.Elem(), off)
		}
	case reflect.Map:
		keys, vals, err := object(raw)
		if err != nil {
			k.fail(path, "want an object")
			return
		}
		for _, key := range keys {
			k.value(path+"["+strconv.Quote(key)+"]", generic+".*", vals[key], t.Elem(), off)
		}
	case reflect.String:
		if first != '"' {
			k.fail(path, "want a string")
		}
	case reflect.Bool:
		if string(raw) != "true" && string(raw) != "false" {
			k.fail(path, "want true or false")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if off && string(raw) == `"off"` {
			return
		}
		if first != '-' && (first < '0' || first > '9') {
			if off {
				k.fail(path, `want a number or "off"`)
			} else {
				k.fail(path, "want a number")
			}
		}
	}
}

func (k *keyCheck) duration(path string, raw json.RawMessage, off bool) {
	var d Duration
	if err := json.Unmarshal(raw, &d); err != nil {
		k.fail(path, "%v", err)
		return
	}
	switch {
	case d == Off && string(raw) == `"off"` && !off:
		k.fail(path, `"off" isn't allowed here`)
	case d < 0 && string(raw) != `"off"` && off:
		k.fail(path, `negative no longer means off: write "off"`)
	case d < 0 && string(raw) != `"off"`:
		k.fail(path, "must not be negative, got %s", time.Duration(d))
	}
}

// object returns a JSON object's keys in document order, and their values.
func object(b []byte) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errors.New("want an object")
	}
	var keys []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		if _, dup := vals[key]; dup {
			return nil, nil, fmt.Errorf("key %s appears twice", key)
		}
		keys = append(keys, key)
		vals[key] = v
	}
	return keys, vals, nil
}

// suggest returns the known name closest to key: same letters in another case, or at most two edits away, nearest length first.
func suggest(key string, names []string) string {
	best, bestD, bestL := "", 3, 0
	for _, n := range names {
		if strings.EqualFold(n, key) {
			return n
		}
		d, l := distance(strings.ToLower(key), strings.ToLower(n)), abs(len(n)-len(key))
		if d <= len(n)/2 && (d < bestD || d == bestD && l < bestL) {
			best, bestD, bestL = n, d, l
		}
	}
	return best
}

func abs(n int) int { return max(n, -n) }

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
