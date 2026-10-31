package fleetdrift

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestReportsFor_Graded verifies the CRD spec carries the graded flag and coverage.
func TestReportsFor_Graded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Score    report.FleetScore
		WantSpec FleetScoreSpec
	}{{ // Test 0: A graded fleet carries its grade.
		Score:    report.FleetScore{Score: 90, Grade: "A", Graded: true, Coverage: report.FleetCoverage{Fraction: 1}},
		WantSpec: FleetScoreSpec{Score: 90, Grade: "A", Graded: true, Coverage: 1},
	}, { // Test 1: An ungraded fleet has an empty grade and its coverage.
		Score:    report.FleetScore{Score: 100, Coverage: report.FleetCoverage{Fraction: 0.5}},
		WantSpec: FleetScoreSpec{Score: 100, Coverage: 0.5},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := &report.Report{Clusters: []string{"c1"}, FleetScore: test.Score}
			got := ReportsFor(r, "scan-1", "ns")
			if len(got) != 1 {
				t.Fatalf("want 1 report, got %d", len(got))
			}
			if diff := cmp.Diff(test.WantSpec, got[0].Spec.FleetScore); diff != "" {
				t.Errorf("spec mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
