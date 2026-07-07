package policyreportingest

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// FuzzIngestReport asserts ingestReport never panics on a PolicyReport-shaped
// object decoded from fuzzed JSON and that the aggregate counts it produces
// stay non-negative and internally consistent. ingestReport reads an untyped
// results slice out of unstructured data, so malformed rows (wrong types,
// missing keys, nested junk) must be tolerated silently. Feeding it bytes that
// went through encoding/json keeps every value JSON-compatible, matching what
// the dynamic client hands the scanner in production.
func FuzzIngestReport(f *testing.F) {
	seeds := []string{
		`{}`,
		`null`,
		`{"results": []}`,
		`{"results": [{"source":"kyverno","policy":"p","rule":"r","result":"fail","severity":"high"}]}`,
		`{"results": [{"result":"pass"},{"result":"warn"},{"result":"error"},{"result":"skip"}]}`,
		`{"results": [{"source":123,"policy":true,"result":["nope"]}]}`,
		`{"results": "not-a-slice"}`,
		`{"results": [null, 42, "x", {"result":"fail","policy":"p"}]}`,
		`{"results": [{"result":"fail"}]}`,
		`{"results": [{"result":"fail","policy":"p","severity":"critical"}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return // Not a JSON object; nothing ingestReport could consume.
		}
		u := &unstructured.Unstructured{Object: obj}

		d := Data{}
		bySource := map[string]*sourceTally{}
		topMap := map[string]*PolicyFailure{}
		ingestReport(u, &d, bySource, topMap)

		if d.TotalFail < 0 || d.TotalWarn < 0 || d.TotalError < 0 {
			t.Errorf("negative total: fail=%d warn=%d error=%d",
				d.TotalFail, d.TotalWarn, d.TotalError)
		}
		// Every recorded top failure counts a subset of the fail rows, so the
		// summed top-failure Fail counts can never exceed the cluster total.
		sumTopFail := 0
		for _, pf := range topMap {
			if pf.Fail < 0 || pf.Warn < 0 {
				t.Errorf("negative top counter: %+v", pf)
			}
			sumTopFail += pf.Fail
		}
		if sumTopFail > d.TotalFail {
			t.Errorf("summed top fail %d exceeds TotalFail %d", sumTopFail, d.TotalFail)
		}
	})
}
