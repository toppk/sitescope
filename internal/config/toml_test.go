package config

import (
	"encoding/json"
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
