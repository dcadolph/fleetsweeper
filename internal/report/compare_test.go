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
		WantUniform         bool
		WantDivergenceCount int
		Clusters            []string
		Results             map[string]map[string]scanner.Result
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

func TestCompare(t *testing.T) {
	t.Parallel()

	type data = map[string]any
	abc := []string{"a", "b", "c"}

	tests := []struct {
		WantUniform     bool
		WantDivergences []Divergence
		Clusters        []string
		PerCluster      map[string]any
	}{{ // Test 0: Empty first string value differs from later values.
		Clusters:    abc,
		PerCluster:  map[string]any{"a": data{"x": ""}, "b": data{"x": "x"}, "c": data{"x": "x"}},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field:  "x",
			Values: map[string]string{"a": "", "b": "x", "c": "x"},
		}},
	}, { // Test 1: Cluster absent from perCluster shows missing for strings.
		Clusters:    abc,
		PerCluster:  map[string]any{"a": data{"x": "1"}, "b": data{"x": "2"}},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field:  "x",
			Values: map[string]string{"a": "1", "b": "2", "c": "<missing>"},
		}},
	}, { // Test 2: Leading nil numeric value still gets numeric annotation.
		Clusters:    abc,
		PerCluster:  map[string]any{"a": data{"n": nil}, "b": data{"n": 5.0}, "c": data{"n": 3.0}},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field:  "n",
			Values: map[string]string{"a": "0 [lowest]", "b": "5 [highest]", "c": "3"},
		}},
	}, { // Test 3: Absent cluster keeps missing and is not annotated for numerics.
		Clusters:    abc,
		PerCluster:  map[string]any{"a": data{"n": 0.0}, "b": data{"n": 2.0}},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field:  "n",
			Values: map[string]string{"a": "0 [lowest]", "b": "2 [highest]", "c": "<missing>"},
		}},
	}, { // Test 4: Set field reports item counts and missing members.
		Clusters: abc,
		PerCluster: map[string]any{
			"a": data{"names": []any{"x", "y"}},
			"b": data{"names": []any{"x"}},
			"c": data{"names": []any{"x", "y"}},
		},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field:  "names",
			Values: map[string]string{"a": "2 items", "b": "1 items, missing: y", "c": "2 items"},
		}},
	}, { // Test 5: Set field with an absent cluster reports all members missing.
		Clusters: abc,
		PerCluster: map[string]any{
			"a": data{"hosts": []any{"h"}},
			"b": data{"hosts": []any{"h", "i"}},
		},
		WantUniform: false,
		WantDivergences: []Divergence{{
			Field: "hosts",
			Values: map[string]string{
				"a": "1 items, missing: i", "b": "2 items", "c": "0 items, missing: h, i",
			},
		}},
	}, { // Test 6: Uniform input yields no divergences.
		Clusters:        abc,
		PerCluster:      map[string]any{"a": data{"x": "1"}, "b": data{"x": "1"}, "c": data{"x": "1"}},
		WantUniform:     true,
		WantDivergences: nil,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := compare(test.Clusters, test.PerCluster)
			if diff := cmp.Diff(test.WantUniform, got.Uniform); diff != "" {
				t.Errorf("uniform mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDivergences, got.Divergences, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("divergences mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
