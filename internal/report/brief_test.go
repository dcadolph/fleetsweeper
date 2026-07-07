package report

import (
	"strings"
	"testing"
)

// TestGenerateBrief verifies the executive summary reflects the report's score,
// incidents, cohort drift, degraded coverage, and top fixes.
func TestGenerateBrief(t *testing.T) {
	t.Parallel()

	r := &Report{
		Clusters:   []string{"a", "b", "c"},
		FleetScore: FleetScore{Score: 73, Grade: "C"},
		Findings: []Finding{
			{Title: "a webhook down", Severity: SeverityCritical, Cluster: "a", Scanner: "admission",
				Remediation: &Remediation{Command: "kubectl get validatingwebhookconfiguration"}},
			{Title: "b cert expiring", Severity: SeverityWarning, Cluster: "b", Scanner: "certs"},
			{Title: "c note", Severity: SeverityInfo, Cluster: "c", Scanner: "version"},
		},
		Incidents: []Incident{
			{Cluster: "a", Title: "a: admission path degraded (2 signals)", Theme: "admission-control", Severity: SeverityCritical},
		},
		Cohorts: []CohortSummary{{
			Name: "prod", Outliers: []OutlierResult{{Cluster: "b", Field: "node_count"}},
		}},
		Degraded: []ScannerStatus{{Cluster: "c", Scanner: "metrics", State: "errored"}},
	}

	b := GenerateBrief(r)

	// Test 0: headline carries the score, counts, and incident total.
	for _, want := range []string{"score 73 (C)", "3 clusters", "1 critical", "1 warning", "1 incidents"} {
		if !strings.Contains(b.Headline, want) {
			t.Errorf("headline missing %q: %s", want, b.Headline)
		}
	}

	joined := strings.Join(b.Lines, "\n")
	// Test 1: the worst incident, cohort drift, degraded coverage, and a fix all appear.
	for _, want := range []string{"Worst incident:", "drifted from their cohort", "Coverage is partial", "Fix: a webhook down"} {
		if !strings.Contains(joined, want) {
			t.Errorf("brief lines missing %q:\n%s", want, joined)
		}
	}
	// The fix line should include the remediation command.
	if !strings.Contains(joined, "kubectl get validatingwebhookconfiguration") {
		t.Errorf("fix line missing remediation command:\n%s", joined)
	}
}
