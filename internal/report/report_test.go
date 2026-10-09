package report

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// A hub must read reports from the previous release during a rolling update, and the reverse.
func TestReportCompat(t *testing.T) {
	b, err := os.ReadFile("../../testdata/compat/report-1.3.0.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("a 1.3.0 field was removed or renamed: %v", err)
	}
	out, _ := json.Marshal(r)
	var want, got any
	json.Unmarshal(b, &want)
	json.Unmarshal(out, &got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a 1.3.0 field changed shape:\nwant %s\ngot  %s", b, out)
	}
}
