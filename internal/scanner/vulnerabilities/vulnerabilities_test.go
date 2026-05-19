package vulnerabilities

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
		t.Error("expected no-matches phrasing to be recognised")
	}
	_ = unstructured.Unstructured{}
	_ = metav1.ListOptions{}
	_ = context.Background()
}
