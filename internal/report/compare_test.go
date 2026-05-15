package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantUniform bool
		WantDivergenceCount int
		Clusters    []string
		Results     map[string]map[string]scanner.Result
	}{{ // Test 0: Uniform clusters.
		Clusters: []string{"a", "b"},
		Results: map[string]map[string]scanner.Result{
			"a": {"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.28.3"}}},
			"b": {"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.28.3"}}},
		},
		WantUniform:         true,
		WantDivergenceCount: 0,
	}, { // Test 1: Divergent clusters.
		Clusters: []string{"a", "b"},
		Results: map[string]map[string]scanner.Result{
			"a": {"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.28.3"}}},
			"b": {"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.29.0"}}},
		},
		WantUniform:         false,
		WantDivergenceCount: 1,
	}, { // Test 2: Single cluster is always uniform.
		Clusters: []string{"a"},
		Results: map[string]map[string]scanner.Result{
			"a": {"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.28.3"}}},
		},
		WantUniform:         true,
		WantDivergenceCount: 0,
	}, { // Test 3: Multiple divergent fields.
		Clusters: []string{"a", "b"},
		Results: map[string]map[string]scanner.Result{
			"a": {"version": {Scanner: "version", Data: map[string]string{"major": "1", "minor": "28"}}},
			"b": {"version": {Scanner: "version", Data: map[string]string{"major": "1", "minor": "29"}}},
		},
		WantUniform:         false,
		WantDivergenceCount: 1,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			rpt := Build(test.Clusters, test.Results)

			section, ok := rpt.Sections["version"]
			if !ok {
				t.Fatal("expected version section")
			}
			if diff := cmp.Diff(test.WantUniform, section.Uniform); diff != "" {
				t.Errorf("uniform mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDivergenceCount, len(section.Divergences), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("divergence count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
