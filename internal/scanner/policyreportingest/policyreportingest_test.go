package policyreportingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
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

// absentErr builds the NotFound error the apiserver returns for a list of a CRD that is not installed.
func absentErr(resource string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "wgpolicyk8s.io", Resource: resource}, "")
}

// policyDynamic returns a dynamic fake serving the PolicyReport and
// ClusterPolicyReport list kinds. Any resource named in listErrs fails its list
// with the mapped error, letting a test model an absent or unreadable CRD.
func policyDynamic(listErrs map[string]error) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		policyReportGVR:        "PolicyReportList",
		clusterPolicyReportGVR: "ClusterPolicyReportList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
	for res, listErr := range listErrs {
		dyn.PrependReactor("list", res, func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, listErr
		})
	}
	return dyn
}

// TestScanBothCRDsAbsentUnavailable verifies that when neither PolicyReport CRD
// is installed the scanner reports unavailable rather than a clean empty result.
func TestScanBothCRDsAbsentUnavailable(t *testing.T) {
	t.Parallel()

	absent := absentErr(policyReportGVR.Resource)
	dyn := policyDynamic(map[string]error{
		policyReportGVR.Resource:        absent,
		clusterPolicyReportGVR.Resource: absent,
	})
	client := kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != scanner.StateUnavailable {
		t.Errorf("state: want %q, got %q", scanner.StateUnavailable, result.State)
	}
	if !strings.Contains(result.Reason, "not served") {
		t.Errorf("reason should say the types are not served, got %q", result.Reason)
	}
	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}
	if data.Available {
		t.Error("Available should be false when both CRDs are absent")
	}
}

// TestScanOneAbsentOneReadableOK verifies that one CRD being uninstalled while
// the other is present is a normal, available result.
func TestScanOneAbsentOneReadableOK(t *testing.T) {
	t.Parallel()

	dyn := policyDynamic(map[string]error{
		clusterPolicyReportGVR.Resource: absentErr(clusterPolicyReportGVR.Resource),
	})
	client := kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != scanner.StateOK {
		t.Errorf("state: want OK, got %q", result.State)
	}
	data := result.Data.(Data)
	if !data.Available {
		t.Error("Available should be true when one CRD is present")
	}
}

// TestScanReadableAndErroredDegrades verifies that a real (non-absent) error on
// one report type while the other is readable yields a degraded result naming
// the failed list, so missing reports do not read as a clean cluster.
func TestScanReadableAndErroredDegrades(t *testing.T) {
	t.Parallel()

	dyn := policyDynamic(map[string]error{
		clusterPolicyReportGVR.Resource: apierrors.NewForbidden(
			schema.GroupResource{Resource: clusterPolicyReportGVR.Resource}, "", errors.New("access denied")),
	})
	client := kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != scanner.StateDegraded {
		t.Errorf("state: want degraded, got %q", result.State)
	}
	if !strings.Contains(result.Reason, "cluster policy reports") {
		t.Errorf("reason should name cluster policy reports, got %q", result.Reason)
	}
	data := result.Data.(Data)
	if !data.Available {
		t.Error("Available should be true when one report type is readable")
	}
}

// TestScanListErrors verifies a failed list is classified instead of read as an empty cluster.
func TestScanListErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Err       error
		Want      error
		WantState scanner.State
	}{{ // Test 0: Forbidden lists error the scan.
		Err:  apierrors.NewForbidden(schema.GroupResource{Resource: "x"}, "", errors.New("rbac denied")),
		Want: scanner.ErrScan, WantState: scanner.StateErrored,
	}, { // Test 1: A resource type the server does not serve is unavailable.
		Err:       apierrors.NewNotFound(schema.GroupResource{Resource: "x"}, ""),
		WantState: scanner.StateUnavailable,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{policyReportGVR: "PolicyReportList", clusterPolicyReportGVR: "ClusterPolicyReportList"})
			dyn.PrependReactor("list", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, test.Err
			})
			client := kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)
			result, err := NewScanner().Scan(context.Background(), client)
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if result.State != test.WantState {
				t.Errorf("state = %q, want %q", result.State, test.WantState)
			}
		})
	}
}
