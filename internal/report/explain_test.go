package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
				if f.Rule == "security/outlier-enforced-count" {
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
