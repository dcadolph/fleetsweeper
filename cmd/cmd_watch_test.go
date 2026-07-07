package cmd

import (
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/compare"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestDiffHasChanges verifies each meaningful diff field flips the result to
// true while a zero-value diff reports no change.
func TestDiffHasChanges(t *testing.T) {
	t.Parallel()
	finding := report.Finding{Title: "t"}
	tests := []struct {
		In       compare.ScanDiff
		WantBool bool
	}{
		{In: compare.ScanDiff{}, WantBool: false},                                                                   // Test 0: Empty diff.
		{In: compare.ScanDiff{New: []report.Finding{finding}}, WantBool: true},                                      // Test 1: New finding.
		{In: compare.ScanDiff{Resolved: []report.Finding{finding}}, WantBool: true},                                 // Test 2: Resolved finding.
		{In: compare.ScanDiff{AddedClusters: []string{"a"}}, WantBool: true},                                        // Test 3: Added cluster.
		{In: compare.ScanDiff{RemovedClusters: []string{"a"}}, WantBool: true},                                      // Test 4: Removed cluster.
		{In: compare.ScanDiff{ScoreBefore: 80, ScoreAfter: 70}, WantBool: true},                                     // Test 5: Score moved.
		{In: compare.ScanDiff{ClusterStatusChanges: []compare.ClusterStatusChange{{Cluster: "a"}}}, WantBool: true}, // Test 6: Status change.
	}
	for testNum, test := range tests {
		t.Run("case", func(t *testing.T) {
			t.Parallel()
			if got := diffHasChanges(test.In); got != test.WantBool {
				t.Errorf("test %d: got %v, want %v", testNum, got, test.WantBool)
			}
		})
	}
}
