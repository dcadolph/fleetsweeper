package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/compare"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
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

// TestWatchOnce verifies each watchOnce call saves one scan when a store is given and none
// when it is not.
func TestWatchOnce(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WithStore bool
		Runs      int
		WantScans int
	}{
		{ // Test 0: Two runs with a store.
			WithStore: true, Runs: 2, WantScans: 2,
		},
		{ // Test 1: Two runs without a store.
			WithStore: false, Runs: 2, WantScans: 0,
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			st, err := store.NewSQLite(filepath.Join(t.TempDir(), "watch.db"))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer st.Close()
			var use store.Store
			if test.WithStore {
				use = st
			}
			clients := []*kube.Client{kube.NewTestClientWithClientset("c1", fake.NewSimpleClientset())}
			selected, err := selectScanners(buildRegistry(), []string{"namespaces"})
			if err != nil {
				t.Fatalf("select scanners: %v", err)
			}
			for range test.Runs {
				if _, err := watchOnce(ctx, clients, selected, 1, time.Second, use); err != nil {
					t.Fatalf("watchOnce: %v", err)
				}
			}
			scans, err := st.ListScans(ctx, 10)
			if err != nil {
				t.Fatalf("list scans: %v", err)
			}
			if diff := cmp.Diff(test.WantScans, len(scans)); diff != "" {
				t.Errorf("scan count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
