package report

import (
	"strings"
	"testing"
)

// TestCohortOutlierFindings verifies that within-cohort outliers become
// findings and that an outlier already reported against the whole fleet is not
// counted twice.
func TestCohortOutlierFindings(t *testing.T) {
	t.Parallel()

	r := &Report{
		Clusters: []string{"a", "b", "c"},
		Outliers: []OutlierResult{
			{Cluster: "a", Field: "node_count", Scanner: "resources", Value: "50", FleetNorm: "10", Severity: SeverityWarning},
		},
		Cohorts: []CohortSummary{{
			Name:     "auto-1",
			Source:   "auto",
			Clusters: []string{"a", "b", "c"},
			Outliers: []OutlierResult{
				{Cluster: "b", Field: "crd_count", Scanner: "crds", Value: "30", FleetNorm: "5", Severity: SeverityWarning},
				// Duplicate of a fleet-level outlier; must be skipped.
				{Cluster: "a", Field: "node_count", Scanner: "resources", Value: "50", FleetNorm: "10", Severity: SeverityWarning},
			},
		}},
	}

	got := cohortOutlierFindings(r)

	// Test 0: only the non-duplicate cohort outlier becomes a finding.
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Cluster != "b" || got[0].Scanner != "crds" {
		t.Errorf("finding = %s/%s, want b/crds", got[0].Cluster, got[0].Scanner)
	}
	if !strings.Contains(got[0].Description, `cohort "auto-1"`) {
		t.Errorf("description missing cohort name: %q", got[0].Description)
	}
}

// TestGenerateFindingsIncludesCohortOutliers verifies the cohort outliers reach
// the main findings pipeline, so they flow into the fleet score and alerts.
func TestGenerateFindingsIncludesCohortOutliers(t *testing.T) {
	t.Parallel()

	r := &Report{
		Clusters: []string{"a", "b"},
		Sections: map[string]*SectionReport{},
		Cohorts: []CohortSummary{{
			Name:     "prod",
			Source:   "tagged",
			Clusters: []string{"a", "b", "c"},
			Outliers: []OutlierResult{
				{Cluster: "b", Field: "avg_cpu_percent", Scanner: "metrics", Value: "92", FleetNorm: "40", Severity: SeverityCritical},
			},
		}},
	}

	var found bool
	for _, f := range GenerateFindings(r) {
		if f.Cluster == "b" && f.Scanner == "metrics" && strings.Contains(f.Description, "cohort") {
			found = true
		}
	}
	if !found {
		t.Errorf("GenerateFindings did not include the cohort outlier finding")
	}
}
