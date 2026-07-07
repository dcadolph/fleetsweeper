package server

import "testing"

// TestDemoReportRunsRealEngine verifies that serve --demo exercises the real
// report engine: the synthetic fleet produces populated per-scanner sections,
// fleet-level outliers, cohorts, and degraded coverage, rather than hand-faked
// data with an empty Sections map.
func TestDemoReportRunsRealEngine(t *testing.T) {
	t.Parallel()

	r := demoReport()

	if len(r.Sections) == 0 {
		t.Fatal("demo report has no per-scanner sections; the outlier engine cannot run")
	}
	// The demo fleet has more than 20 clusters, so fleet-level MAD outliers fire.
	if len(r.Outliers) == 0 {
		t.Error("expected fleet-level outliers from the demo data")
	}
	if len(r.Cohorts) == 0 {
		t.Error("expected cohorts from the demo data")
	}
	// One scanner is planted as errored, so degraded coverage must surface
	// instead of a false all-clear.
	if len(r.Degraded) == 0 {
		t.Error("expected degraded coverage from the planted errored scanner")
	}
	if len(r.Findings) == 0 {
		t.Error("expected findings from the engine plus curated narratives")
	}
}
