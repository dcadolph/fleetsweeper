package report

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestExplainByCohort verifies a fleet outlier that its tagged cohort holds
// within the cohort's norm raises no finding and has its deviation measured
// against the cohort, while one outside its cohort's norm, or one with no
// tag, keeps its finding.
func TestExplainByCohort(t *testing.T) {
	t.Parallel()
	// Fourteen small clusters near 10, then six big ones near 40 with c18 at 80. At fleet scope
	// every big cluster is an outlier.
	values := []float64{9, 10, 10, 11, 10, 9, 11, 10, 10, 12, 10, 11, 9, 10, 38, 40, 41, 40, 80, 39}
	tests := []struct {
		WantExplained  map[string]string
		WantFindingFor []string
		Tagged         bool
	}{{ // Test 0: Tagged; the big cohort holds its members near 40 but not c18 at 80.
		Tagged:         true,
		WantExplained:  map[string]string{"c14": "big", "c15": "big", "c16": "big", "c17": "big", "c19": "big"},
		WantFindingFor: []string{"c18"},
	}, { // Test 1: Untagged; every fleet outlier keeps its finding.
		WantFindingFor: []string{"c14", "c15", "c16", "c17", "c18", "c19"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := enforcedFleet(values...)
			var tags map[string]string
			if test.Tagged {
				tags = map[string]string{}
				for i, c := range clusters {
					tags[c] = map[bool]string{true: "small", false: "big"}[i < 14]
				}
			}
			r := Build(clusters, results, BuildOptions{ClusterTags: tags})
			explained := map[string]string{}
			for _, o := range r.Outliers {
				if o.ExplainedBy != "" {
					explained[o.Cluster] = o.ExplainedBy
				}
			}
			if diff := cmp.Diff(test.WantExplained, explained, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("explained mismatch (-want +got):\n%s", diff)
			}
			var flagged []string
			for _, f := range r.Findings {
				if f.Rule == "security/outlier-unenforced-count" {
					flagged = append(flagged, f.Cluster)
				}
			}
			if diff := cmp.Diff(test.WantFindingFor, flagged, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("fleet outlier findings mismatch (-want +got):\n%s", diff)
			}
			for c := range test.WantExplained {
				if r.DeviationMass[c] >= 3.5 {
					t.Errorf("%s is explained but carries fleet-sized deviation mass %v", c, r.DeviationMass[c])
				}
			}
			if r.DeviationMass["c18"] == 0 {
				t.Error("c18 lost its deviation mass")
			}
		})
	}
}

// TestExplainByTaggedPair verifies a tagged cohort of two, too small for a norm of its own,
// holds a fleet outlier only when both members deviate the same way, and that a tagged cohort
// of one holds nothing and says so in the notes.
func TestExplainByTaggedPair(t *testing.T) {
	t.Parallel()
	const lone = "Cohort edge has one cluster, so it holds no outlier."
	tests := []struct {
		Edge           [2]float64
		Tagged         []string
		WantExplained  map[string]string
		WantFindingFor []string
		WantNote       bool
	}{{ // Test 0: Both edge clusters run far fewer nodes than the fleet, so the pair holds both.
		Edge:          [2]float64{2, 3},
		Tagged:        []string{"e0", "e1"},
		WantExplained: map[string]string{"e0": "edge", "e1": "edge"},
	}, { // Test 1: The edge clusters deviate on opposite sides, so each keeps its finding.
		Edge:           [2]float64{2, 30},
		Tagged:         []string{"e0", "e1"},
		WantFindingFor: []string{"e0", "e1"},
	}, { // Test 2: A lone tagged cluster holds nothing and the note says why.
		Edge:           [2]float64{2, 3},
		Tagged:         []string{"e0"},
		WantFindingFor: []string{"e0", "e1"},
		WantNote:       true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			values := []float64{9, 10, 10, 11, 10, 9, 11, 10}
			clusters := make([]string, 0, len(values)+2)
			results := make(map[string]map[string]scanner.Result, len(values)+2)
			add := func(c string, v float64) {
				clusters = append(clusters, c)
				results[c] = map[string]scanner.Result{
					"resources": {Scanner: "resources", Data: map[string]any{"node_count": v}},
				}
			}
			for i, v := range values {
				add(fmt.Sprintf("c%02d", i), v)
			}
			add("e0", test.Edge[0])
			add("e1", test.Edge[1])
			tags := map[string]string{}
			for _, c := range test.Tagged {
				tags[c] = "edge"
			}
			r := Build(clusters, results, BuildOptions{ClusterTags: tags})
			explained := map[string]string{}
			for _, o := range r.Outliers {
				if o.ExplainedBy != "" {
					explained[o.Cluster] = o.ExplainedBy
				}
			}
			if diff := cmp.Diff(test.WantExplained, explained, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("explained mismatch (-want +got):\n%s", diff)
			}
			var flagged []string
			for _, f := range r.Findings {
				if f.Rule == "resources/outlier-node-count" {
					flagged = append(flagged, f.Cluster)
				}
			}
			sortStrings := cmpopts.SortSlices(func(a, b string) bool { return a < b })
			if diff := cmp.Diff(test.WantFindingFor, flagged, sortStrings, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("fleet outlier findings mismatch (-want +got):\n%s", diff)
			}
			if got := slices.Contains(r.Notes, lone); got != test.WantNote {
				t.Errorf("lone cohort note present = %v, want %v (notes %q)", got, test.WantNote, r.Notes)
			}
		})
	}
}
