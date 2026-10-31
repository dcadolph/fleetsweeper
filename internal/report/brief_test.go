package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestGenerateBrief verifies the executive summary reflects the report's score,
// incidents, cohort drift, degraded coverage, and top fixes.
func TestGenerateBrief(t *testing.T) {
	t.Parallel()

	r := &Report{
		Clusters: []string{"a", "b", "c"},
		FleetScore: FleetScore{
			Score: 73, Grade: "C", Graded: true, SampleSize: 3, Dimensions: 24, ExcludedClusters: 1,
		},
		Findings: []Finding{
			{Title: "a webhook down", Severity: SeverityCritical, Cluster: "a", Scanner: "admission",
				Remediation: &Remediation{Command: "kubectl get validatingwebhookconfiguration"}},
			{Title: "b cert expiring", Severity: SeverityWarning, Cluster: "b", Scanner: "certs"},
			{Title: "c note", Severity: SeverityInfo, Cluster: "c", Scanner: "version"},
			{Title: "b deviates from its cohort on node_count", Severity: SeverityInfo, Cluster: "b",
				Scanner: "resources", Affected: []string{"node_count"},
				Norm: &NormBasis{Scope: "prod", Kind: NormKindNumeric, Median: 3, SampleSize: 5, Value: "9"}},
		},
		Incidents: []Incident{
			{Cluster: "a", Title: "a: admission path degraded (2 signals)", Theme: "admission-control", Severity: SeverityCritical},
		},
		Cohorts: []CohortSummary{{
			Name: "prod", Outliers: []OutlierResult{{Cluster: "b", Field: "node_count"}},
		}},
		Degraded: []ScannerStatus{{Cluster: "c", Scanner: "metrics", State: "errored"}},
	}

	b := generateBrief(r)

	// Test 0: headline carries the score, provenance, counts, and incident total.
	for _, want := range []string{
		"score 73 (C)", "3 clusters", "24 dimensions", "1 critical", "1 warning", "1 incidents",
	} {
		if !strings.Contains(b.Headline, want) {
			t.Errorf("headline missing %q: %s", want, b.Headline)
		}
	}

	joined := strings.Join(b.Lines, "\n")
	// Test 1: the excluded-cluster note, worst incident, cohort drift, degraded
	// coverage, and a fix all appear.
	for _, want := range []string{
		"1 cluster(s) excluded from the score", "Worst incident:",
		"drifted from their cohort", "Coverage is partial", "Fix: a webhook down",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("brief lines missing %q:\n%s", want, joined)
		}
	}
	// The fix line should include the remediation command.
	if !strings.Contains(joined, "kubectl get validatingwebhookconfiguration") {
		t.Errorf("fix line missing remediation command:\n%s", joined)
	}
}

// TestGenerateBriefCoverage verifies the brief leads with coverage when the score is not graded
// and names blind runs when it is.
func TestGenerateBriefCoverage(t *testing.T) {
	t.Parallel()
	clusters := []string{"c1", "c2"}
	allErrored := map[runKey]*scanner.Result{}
	for _, c := range clusters {
		for _, s := range []string{"s1", "s2", "s3"} {
			allErrored[runKey{scanner: s, cluster: c}] = runOf(erroredRun(s))
		}
	}
	tests := []struct {
		Name         string
		Override     map[runKey]*scanner.Result
		WantHeadline string
		WantFirst    string
		WantLine     string
		WantNoLine   string
	}{{ // Test 0: Every run errored, so the coverage sentence is the first line.
		Name:     "all errored",
		Override: allErrored,
		WantHeadline: "Not enough data: 6 of 6 scanner runs did not observe the fleet, " +
			"and 2 of 2 clusters had no complete scanner run.",
		WantFirst:  "Observed-only score 100",
		WantNoLine: "Coverage is partial",
	}, { // Test 1: One blind run on a graded fleet adds the coverage sentence to the lines.
		Name: "graded with a blind run",
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c1"}: runOf(erroredRun("s1")),
		},
		WantHeadline: "Fleet score 100 (A)",
		WantLine:     "1 of 6 scanner runs did not observe the fleet.",
		WantNoLine:   "Coverage is partial",
	}, { // Test 2: A fully observed fleet carries no coverage sentence.
		Name:         "fully observed",
		WantHeadline: "Fleet score 100 (A)",
		WantNoLine:   "scanner runs",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			r := Build(clusters, coverageResults(clusters, 3, test.Override))
			b := r.Brief
			if !strings.HasPrefix(b.Headline, test.WantHeadline) {
				t.Errorf("brief headline %q, want prefix %q", b.Headline, test.WantHeadline)
			}
			if test.WantFirst != "" {
				if len(b.Lines) == 0 {
					t.Fatalf("brief has no lines, want first %q", test.WantFirst)
				}
				if !strings.HasPrefix(b.Lines[0], test.WantFirst) {
					t.Errorf("first line %q, want prefix %q", b.Lines[0], test.WantFirst)
				}
			}
			joined := strings.Join(b.Lines, "\n")
			if test.WantLine != "" && !strings.Contains(joined, test.WantLine) {
				t.Errorf("brief lines missing %q:\n%s", test.WantLine, joined)
			}
			if test.WantNoLine != "" && strings.Contains(joined, test.WantNoLine) {
				t.Errorf("brief lines carry %q:\n%s", test.WantNoLine, joined)
			}
			gradedHead := !strings.HasPrefix(b.Headline, "Not enough data")
			if diff := cmp.Diff(r.FleetScore.Graded, gradedHead); diff != "" {
				t.Errorf("brief headline disagrees with Graded (-want +got):\n%s", diff)
			}
		})
	}
}
