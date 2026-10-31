package seal

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestMetadata_Graded verifies the metadata score line follows the Graded flag.
func TestMetadata_Graded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Score    report.FleetScore
		WantLine string
	}{{ // Test 0: A graded fleet prints the score and grade.
		Score:    report.FleetScore{Score: 82, Grade: "B", Graded: true},
		WantLine: "Fleet score:   82 (B)",
	}, { // Test 1: An ungraded fleet prints the coverage.
		Score:    report.FleetScore{Score: 100, Coverage: report.FleetCoverage{Fraction: 0.25}},
		WantLine: "Fleet score:   not graded (coverage 25%)",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := string(metadata(&report.Report{FleetScore: test.Score}, "scan-1", BundleOptions{}))
			if !strings.Contains(got, test.WantLine) {
				t.Errorf("metadata missing %q:\n%s", test.WantLine, got)
			}
		})
	}
}
