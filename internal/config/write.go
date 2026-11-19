package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

func readDoc(doc []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	root, err := readNode(dec)
	if err != nil {
		return nil, err
	}
	if !root.isObj {
		return nil, errors.New("want an object")
	}
	return root, nil
}

// WriteJSON writes a JSON config document for people: small objects and lists on one line, null values left out.
func WriteJSON(w io.Writer, doc []byte) error {
	root, err := readDoc(doc)
	if err != nil {
		return err
	}
	var b strings.Builder
	writeJSONNode(&b, root, "")
	b.WriteByte('\n')
	_, err = io.WriteString(w, b.String())
	return err
}

func jsonOneLine(n *node) string {
	switch {
	case n.isObj:
		var parts []string
		for _, k := range n.keys {
			if c := n.obj[k]; !c.null() {
				kj, _ := json.Marshal(k)
				parts = append(parts, string(kj)+": "+jsonOneLine(c))
			}
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case n.isArr:
		var parts []string
		for _, c := range n.arr {
			parts = append(parts, jsonOneLine(c))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return string(n.raw)
}

// flat reports whether n fits on one line: a scalar, a small object, or a short list of them.
func (n *node) flat() bool {
	switch {
	case n.isObj:
		return n.small()
	case n.isArr:
		for _, c := range n.arr {
			if c.isArr || c.isObj && !c.small() {
				return false
			}
		}
		return len(n.arr) == 0 || !n.arr[0].isObj && len(jsonOneLine(n)) <= 80 || len(n.arr) == 1 && n.arr[0].small()
	}
	return true
}

func writeJSONNode(b *strings.Builder, n *node, indent string) {
	if n.flat() && indent != "" {
		b.WriteString(jsonOneLine(n))
		return
	}
	in := indent + "  "
	if n.isArr {
		b.WriteString("[\n")
		for i, c := range n.arr {
			b.WriteString(in)
			writeJSONNode(b, c, in)
			if i < len(n.arr)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(indent + "]")
		return
	}
	var keys []string
	for _, k := range n.keys {
		if !n.obj[k].null() {
			keys = append(keys, k)
		}
	}
	b.WriteString("{\n")
	for i, k := range keys {
		kj, _ := json.Marshal(k)
		b.WriteString(in + string(kj) + ": ")
		writeJSONNode(b, n.obj[k], in)
		if i < len(keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(indent + "}")
}

var (
	nixIdent    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_'-]*$`)
	nixReserved = []string{"assert", "else", "if", "in", "inherit", "let", "or", "rec", "then", "with"}
)

func nixKey(k string) string {
	if nixIdent.MatchString(k) && !slices.Contains(nixReserved, k) {
		return k
	}
	return nixString(k)
}

func nixString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "${", `\${`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

func nixScalar(n *node) string {
	if len(n.raw) > 0 && n.raw[0] == '"' {
		var s string
		json.Unmarshal(n.raw, &s)
		return nixString(s)
	}
	return string(n.raw)
}

// WriteNix writes a JSON config document as a Nix attribute set, as for services.sitescope.settings; null values are left out.
func WriteNix(w io.Writer, doc []byte) error {
	root, err := readDoc(doc)
	if err != nil {
		return err
	}
	var b strings.Builder
	writeNixNode(&b, root, "")
	b.WriteByte('\n')
	_, err = io.WriteString(w, b.String())
	return err
}

func nixOneLine(n *node) string {
	switch {
	case n.isObj:
		var parts []string
		for _, k := range n.keys {
			if c := n.obj[k]; !c.null() {
				p, v := nixPath(k, c)
				parts = append(parts, p+" = "+nixOneLine(v)+";")
			}
		}
		if len(parts) == 0 {
			return "{ }"
		}
		return "{ " + strings.Join(parts, " ") + " }"
	case n.isArr:
		if len(n.arr) == 0 {
			return "[ ]"
		}
		var parts []string
		for _, c := range n.arr {
			parts = append(parts, nixOneLine(c))
		}
		return "[ " + strings.Join(parts, " ") + " ]"
	}
	return nixScalar(n)
}

// nixPath folds a chain of one-key objects into a dotted path, as in tls.targets = [ … ].
func nixPath(k string, n *node) (string, *node) {
	p := nixKey(k)
	for n.isObj && len(n.keys) == 1 && !n.obj[n.keys[0]].null() {
		p += "." + nixKey(n.keys[0])
		n = n.obj[n.keys[0]]
	}
	return p, n
}

func writeNixNode(b *strings.Builder, n *node, indent string) {
	if n.flat() && indent != "" {
		b.WriteString(nixOneLine(n))
		return
	}
	in := indent + "  "
	if n.isArr {
		b.WriteString("[\n")
		for _, c := range n.arr {
			b.WriteString(in)
			writeNixNode(b, c, in)
			b.WriteByte('\n')
		}
		b.WriteString(indent + "]")
		return
	}
	b.WriteString("{\n")
	for _, k := range n.keys {
		c := n.obj[k]
		if c.null() {
			continue
		}
		p, v := nixPath(k, c)
		b.WriteString(in + p + " = ")
		writeNixNode(b, v, in)
		b.WriteString(";\n")
	}
	b.WriteString(indent + "}")
}

// ConvertTOML writes a TOML document as json, nix or toml, keeping its keys as written.
func ConvertTOML(w io.Writer, b []byte, format string) error {
	doc, err := fromTOML(b)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		return WriteJSON(w, doc)
	case "nix":
		return WriteNix(w, doc)
	case "toml":
		return WriteTOML(w, doc)
	}
	return fmt.Errorf("format %q, want json, nix or toml", format)
}
