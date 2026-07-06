package policyreportingest

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// fakeReport builds a PolicyReport-shaped unstructured object with the
// provided results list.
func fakeReport(results []map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "wgpolicyk8s.io/v1alpha2",
			"kind":       "PolicyReport",
			"metadata":   map[string]any{"name": "r"},
			"results":    asAnySlice(results),
		},
	}
}

// asAnySlice coerces a typed slice of maps into the []any form
// unstructured.NestedSlice expects.
func asAnySlice(in []map[string]any) []any {
	out := make([]any, len(in))
	for i, r := range in {
		out[i] = r
	}
	return out
}

// TestIngestReport_SeparatesSources verifies one PolicyReport carrying
// rows from two different tools tallies them independently.
func TestIngestReport_SeparatesSources(t *testing.T) {
	t.Parallel()
	obj := fakeReport([]map[string]any{
		{"source": "kyverno", "policy": "require-labels", "result": "fail", "severity": "high"},
		{"source": "kyverno", "policy": "require-labels", "result": "fail", "severity": "high"},
		{"source": "gatekeeper", "policy": "k8spsphostnetwork", "result": "fail", "severity": "critical"},
		{"source": "kyverno", "policy": "require-limits", "result": "pass"},
		{"source": "trivy", "policy": "cve-scan", "result": "warn"},
	})
	data := Data{}
	bySource := map[string]*sourceTally{}
	topMap := map[string]*PolicyFailure{}
	ingestReport(obj, &data, bySource, topMap)

	if data.TotalFail != 3 {
		t.Errorf("TotalFail: want 3, got %d", data.TotalFail)
	}
	if data.TotalWarn != 1 {
		t.Errorf("TotalWarn: want 1, got %d", data.TotalWarn)
	}
	if bySource["kyverno"].Fail != 2 || bySource["kyverno"].Pass != 1 {
		t.Errorf("kyverno tally: %+v", bySource["kyverno"])
	}
	if bySource["gatekeeper"].Fail != 1 {
		t.Errorf("gatekeeper tally: %+v", bySource["gatekeeper"])
	}
	if bySource["trivy"].Warn != 1 {
		t.Errorf("trivy tally: %+v", bySource["trivy"])
	}
}

// TestUpdateTop_DescendingFailRanking verifies the worst-N list is
// sorted by fail count descending.
func TestUpdateTop_DescendingFailRanking(t *testing.T) {
	t.Parallel()
	topMap := map[string]*PolicyFailure{}
	for range 5 {
		updateTop(topMap, "kyverno", "policy-a", "rule-a", "high", "fail")
	}
	for range 2 {
		updateTop(topMap, "kyverno", "policy-b", "rule-b", "low", "fail")
	}
	updateTop(topMap, "kyverno", "policy-c", "", "", "warn")

	top := finalizeTopFailures(topMap, 10)
	if len(top) != 3 {
		t.Fatalf("want 3 entries, got %d", len(top))
	}
	if top[0].Policy != "policy-a" || top[0].Fail != 5 {
		t.Errorf("first should be policy-a/fail=5, got %+v", top[0])
	}
	if top[1].Policy != "policy-b" || top[1].Fail != 2 {
		t.Errorf("second should be policy-b/fail=2, got %+v", top[1])
	}
}

// TestSeverityRank_HighestWins verifies updateTop keeps the highest
// severity seen for a (source, policy, rule) tuple.
func TestSeverityRank_HighestWins(t *testing.T) {
	t.Parallel()
	topMap := map[string]*PolicyFailure{}
	updateTop(topMap, "x", "p", "r", "low", "fail")
	updateTop(topMap, "x", "p", "r", "critical", "fail")
	updateTop(topMap, "x", "p", "r", "medium", "fail")
	got := topMap["x|p|r"].Severity
	if got != "critical" {
		t.Errorf("want critical, got %q", got)
	}
}

// TestFinalizeSourceTallies_OrderedByFail verifies the source rollup
// surfaces the worst tool first.
func TestFinalizeSourceTallies_OrderedByFail(t *testing.T) {
	t.Parallel()
	in := map[string]*sourceTally{
		"a": {Source: "a", Fail: 2},
		"b": {Source: "b", Fail: 5},
		"c": {Source: "c", Fail: 0, Pass: 100},
	}
	out := finalizeSourceTallies(in)
	if out[0].Source != "b" {
		t.Errorf("first: want b, got %s", out[0].Source)
	}
}

// TestCRDAvailable_NoMatchTreatedMissing verifies the helper recognizes
// the dynamic-client's "no matches" error pattern.
func TestCRDAvailable_NoMatchTreatedMissing(t *testing.T) {
	t.Parallel()
	if crdAvailable(stringErr("could not find the requested resource")) {
		t.Error("should be treated as missing")
	}
	if !crdAvailable(stringErr("RBAC denied")) {
		t.Error("RBAC errors should NOT be treated as missing")
	}
	if !crdAvailable(nil) {
		t.Error("nil should be available")
	}
}

// stringErr is a tiny error helper for the CRDAvailable test.
type stringErr string

// Error implements the error interface.
func (s stringErr) Error() string { return string(s) }
