package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReferenceTOMLRoundTrip(t *testing.T) {
	b, err := json.Marshal(Reference())
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := WriteTOML(&out, b); err != nil {
		t.Fatal(err)
	}
	back, err := fromTOML([]byte(out.String()))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	var want, got any
	json.Unmarshal(b, &want)
	json.Unmarshal(back, &got)
	if !reflect.DeepEqual(dropNulls(want), got) {
		t.Errorf("reference TOML doesn't read back the same:\n%s", out.String())
	}
	if err := checkKeys(back); err != nil {
		t.Errorf("reference has keys the loader rejects: %v", err)
	}
}

func dropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if e == nil {
				delete(x, k)
			} else {
				x[k] = dropNulls(e)
			}
		}
	case []any:
		for i, e := range x {
			x[i] = dropNulls(e)
		}
	}
	return v
}

var update = flag.Bool("update", false, "rewrite testdata/config.nix")

// TestNixGolden keeps testdata/config.nix equal to config.toml written as Nix; nix flake check evaluates it against config.json.
func TestNixGolden(t *testing.T) {
	b, err := os.ReadFile("../../testdata/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := ConvertTOML(&out, b, "nix"); err != nil {
		t.Fatal(err)
	}
	if *update {
		os.WriteFile("../../testdata/config.nix", out.Bytes(), 0o644)
	}
	want, _ := os.ReadFile("../../testdata/config.nix")
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("testdata/config.nix is stale; go test ./internal/config -run TestNixGolden -update")
	}
}

func TestWriteJSONKeepsValues(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/config.toml")
	doc, err := fromTOML(b)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, doc); err != nil {
		t.Fatal(err)
	}
	var want, got any
	json.Unmarshal(doc, &want)
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("WriteJSON changed the document:\n%s", out.String())
	}
}

func TestNixStrings(t *testing.T) {
	for in, want := range map[string]string{`a"b`: `"a\"b"`, `${x}`: `"\${x}"`, `c:\d`: `"c:\\d"`, "x\ny": `"x\ny"`} {
		if got := nixString(in); got != want {
			t.Errorf("nixString(%q) = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{"name": "name", "/data": `"/data"`, "KEY1=": `"KEY1="`, "in": `"in"`, "a-b": "a-b"} {
		if got := nixKey(in); got != want {
			t.Errorf("nixKey(%q) = %s, want %s", in, got, want)
		}
	}
}
