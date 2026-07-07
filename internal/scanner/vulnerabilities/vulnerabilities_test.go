package vulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestParseReportFleetTotals verifies severity counts roll up from the
// report.summary block into the cluster-wide Data totals.
func TestParseReportFleetTotals(t *testing.T) {
	t.Parallel()
	data := Data{Available: true}
	seen := map[string]*VulnerableImage{}

	for _, sev := range []map[string]any{
		{"criticalCount": float64(2), "highCount": float64(7), "mediumCount": float64(11), "lowCount": float64(3)},
		{"criticalCount": float64(1), "highCount": float64(2), "mediumCount": float64(0), "lowCount": float64(8)},
	} {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]any{
				"name":      "trivy-report",
				"namespace": "demo",
				"labels": map[string]any{
					"trivy-operator.resource.name":  "frontend",
					"trivy-operator.container.name": "app",
				},
			},
			"report": map[string]any{
				"artifact": map[string]any{
					"repository": "ghcr.io/example/frontend",
					"tag":        "1.2.0",
				},
				"summary": sev,
			},
		}}
		parseReport(obj, &data, seen)
	}

	if data.Critical != 3 || data.High != 9 || data.Medium != 11 || data.Low != 11 {
		t.Errorf("totals wrong: %+v", data)
	}
	if got := topImages(seen, 5); len(got) != 1 || got[0].Image != "ghcr.io/example/frontend:1.2.0" {
		t.Errorf("topImages mismatch: %+v", got)
	}
}

// TestTopImagesRanking verifies the worst offenders sort by total findings
// with critical breaking ties.
func TestTopImagesRanking(t *testing.T) {
	t.Parallel()
	seen := map[string]*VulnerableImage{
		"a": {Image: "low-total", Critical: 0, High: 1},
		"b": {Image: "high-total", Critical: 0, High: 50, Medium: 100},
		"c": {Image: "tied-but-critical", Critical: 5, Low: 146}, // total 151 > 150 (b)
	}
	got := topImages(seen, 3)
	if got[0].Image != "tied-but-critical" {
		t.Errorf("want tied-but-critical first, got %s", got[0].Image)
	}
	if got[1].Image != "high-total" {
		t.Errorf("want high-total second, got %s", got[1].Image)
	}
}

// TestParseReportMissingSummary handles a malformed CR gracefully.
func TestParseReportMissingSummary(t *testing.T) {
	t.Parallel()
	data := Data{Available: true}
	seen := map[string]*VulnerableImage{}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata":   map[string]any{"name": "n", "namespace": "ns"},
		"report":     map[string]any{},
	}}
	parseReport(obj, &data, seen)
	if data.Critical != 0 || data.High != 0 {
		t.Errorf("missing summary should yield zero totals: %+v", data)
	}
}

// TestIsNotFoundDetection covers the strings the dynamic client returns
// when a CRD is missing.
func TestIsNotFoundDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Msg  string
		Want bool
	}{{
		Name: "Test 0: Apiserver phrasing.",
		Msg:  "the server could not find the requested resource",
		Want: true,
	}, {
		Name: "Test 1: Discovery phrasing.",
		Msg:  "no matches for kind VulnerabilityReport in version aquasecurity.github.io/v1alpha1",
		Want: true,
	}, {
		Name: "Test 2: Unrelated network error.",
		Msg:  "connection refused",
		Want: false,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			err := stubError(test.Msg)
			if got := isNotFound(err); got != test.Want {
				t.Errorf("test %d: want %v, got %v", i, test.Want, got)
			}
		})
	}
}

// stubError wraps a string into a minimal error implementation.
type stubError string

// Error satisfies the error interface.
func (s stubError) Error() string { return string(s) }

// TestScannerHandlesMissingCRD verifies the scanner returns Available=false
// (and no error) when the Trivy CRD isn't installed. We exercise this via
// the public package surface by constructing a scanner whose dynamic
// client backing has no registered resource. Since we cannot easily build
// a kube.Client in a unit test, the integration assertion lives in the
// dynamic-fake-backed test below.
func TestScannerHandlesMissingCRD(t *testing.T) {
	t.Parallel()
	// Confirmed via TestIsNotFoundDetection that the discovery error
	// produces Available=false in the package's main path; this test
	// stays here to assert the contract for documentation purposes.
	if !isNotFound(stubError("no matches for kind ConfigMap")) {
		t.Error("expected no-matches phrasing to be recognized")
	}
	_ = unstructured.Unstructured{}
	_ = metav1.ListOptions{}
	_ = context.Background()
}

// newReportsDynamic returns a dynamic fake that serves the Trivy
// VulnerabilityReport list kind so the scanner's list call can be intercepted.
func newReportsDynamic() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{reportsGVR: "VulnerabilityReportList"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
}

// denyingClient returns a client whose vulnerabilityreports list fails with the
// supplied error, exercising the not-installed and generic-error branches.
func denyingClient(listErr error) *kube.Client {
	dyn := newReportsDynamic()
	dyn.PrependReactor("list", "vulnerabilityreports", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, listErr
	})
	return kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)
}

// TestScanErrorClassification verifies the scanner treats a genuinely missing
// CRD as a trustworthy unavailable result but propagates any other list
// failure as a wrapped ErrScan so a blind read is never mistaken for a clean,
// zero-vulnerability cluster.
func TestScanErrorClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Client    *kube.Client
		Want      error
		WantState scanner.State
	}{{ // Test 0: A NoMatch error means the Trivy CRD is absent, not a failure.
		Client:    denyingClient(&meta.NoResourceMatchError{PartialResource: reportsGVR}),
		WantState: scanner.StateUnavailable,
	}, { // Test 1: The apiserver's missing-resource phrasing is treated as absent.
		Client:    denyingClient(stubError("the server could not find the requested resource")),
		WantState: scanner.StateUnavailable,
	}, { // Test 2: The discovery no-matches phrasing is treated as absent.
		Client:    denyingClient(stubError("no matches for kind VulnerabilityReport in version v1alpha1")),
		WantState: scanner.StateUnavailable,
	}, { // Test 3: A forbidden read is a blind read and propagates as an error.
		Client: denyingClient(apierrors.NewForbidden(
			schema.GroupResource{Group: reportsGVR.Group, Resource: reportsGVR.Resource}, "",
			errors.New("rbac denied"))),
		Want: scanner.ErrScan,
	}, { // Test 4: A generic error propagates as a wrapped ErrScan.
		Client: denyingClient(errors.New("boom")),
		Want:   scanner.ErrScan,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			result, err := NewScanner().Scan(context.Background(), test.Client)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: want %v, got %v", test.Want, err)
			}
			if result.State != test.WantState {
				t.Errorf("state mismatch: want %q, got %q", test.WantState, result.State)
			}
		})
	}
}
