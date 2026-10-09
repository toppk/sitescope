package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A hub must read reports from the previous release during a rolling update, and the reverse.
func TestReportCompat(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/compat/report-*.json")
	if len(files) < 2 {
		t.Fatalf("fixtures = %v", files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var r Report
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("%s: a field was removed or renamed: %v", f, err)
		}
		out, _ := json.Marshal(r)
		var want, got any
		json.Unmarshal(b, &want)
		json.Unmarshal(out, &got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: a field changed shape:\nwant %s\ngot  %s", f, b, out)
		}
	}
}
