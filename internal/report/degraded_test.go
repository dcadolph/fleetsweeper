package report

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestBuildDegradedCoverage verifies that a failed scan is surfaced as degraded
// coverage and kept out of the statistical population, rather than read as a
// clean, zero-resource cluster.
func TestBuildDegradedCoverage(t *testing.T) {
	t.Parallel()

	clusters := []string{"c1", "c2", "c3"}
	results := map[string]map[string]scanner.Result{
		"c1": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.0"}},
			"certs":   {Scanner: "certs", State: scanner.StateDegraded, Reason: "secrets list failed", Data: map[string]any{"expiring": 1}},
		},
		"c2": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.0"}},
		},
		"c3": {
			"version": {Scanner: "version", State: scanner.StateErrored, Reason: "nodes forbidden"},
		},
	}

	r := Build(clusters, results)

	// Test 0: Errored cluster is excluded from the population; degraded cluster
	// keeps its partial data in the population.
	if _, ok := r.Sections["version"].PerCluster["c3"]; ok {
		t.Errorf("errored cluster c3 must be excluded from version PerCluster")
	}
	if _, ok := r.Sections["certs"].PerCluster["c1"]; !ok {
		t.Errorf("degraded cluster c1 partial data must stay in certs PerCluster")
	}

	// Test 1: Report.Degraded lists every non-OK run, sorted by cluster then scanner.
	wantDegraded := []ScannerStatus{
		{Cluster: "c1", Scanner: "certs", State: "degraded", Reason: "secrets list failed"},
		{Cluster: "c3", Scanner: "version", State: "errored", Reason: "nodes forbidden"},
	}
	if diff := cmp.Diff(wantDegraded, r.Degraded, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Degraded mismatch (-want +got):\n%s", diff)
	}

	// Test 2: DegradedByCluster counts per cluster.
	wantCounts := map[string]int{"c1": 1, "c3": 1}
	if diff := cmp.Diff(wantCounts, r.DegradedByCluster(), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("DegradedByCluster mismatch (-want +got):\n%s", diff)
	}

	// Test 3: ClusterHealth carries the per-cluster degraded count.
	got := make(map[string]int, len(r.ClusterHealths))
	for _, h := range r.ClusterHealths {
		got[h.Name] = h.DegradedScanners
	}
	want := map[string]int{"c1": 1, "c2": 0, "c3": 1}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ClusterHealth.DegradedScanners mismatch (-want +got):\n%s", diff)
	}
}

// TestErroredResult verifies the runner-facing constructor marks state and
// reason so a scanner error becomes visible degraded coverage.
func TestErroredResult(t *testing.T) {
	t.Parallel()

	testErr := errors.New("nodes forbidden")
	got := scanner.ErroredResult("version", testErr)
	if got.State != scanner.StateErrored {
		t.Errorf("state = %q, want %q", got.State, scanner.StateErrored)
	}
	if !got.Blind() {
		t.Errorf("errored result must report Blind() = true")
	}
	if got.Reason != testErr.Error() {
		t.Errorf("reason = %q, want %q", got.Reason, testErr.Error())
	}
}
