package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestComputeFleetScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name      string
		In        *Report
		WantScore int
		WantGrade string
		WantTopDr string
	}{
		{ // Test 0: Nil report scores 100 with placeholder headline.
			Name:      "nil report",
			In:        nil,
			WantScore: 100,
			WantGrade: "A",
		},
		{ // Test 1: Empty report scores 100 with no drivers.
			Name:      "empty report",
			In:        &Report{Clusters: []string{}},
			WantScore: 100,
			WantGrade: "A",
		},
		{ // Test 2: Single warning finding subtracts 1.5 (rounded to 2).
			Name: "one warning",
			In: &Report{
				Clusters: []string{"c1"},
				Findings: []Finding{{Severity: SeverityWarning}},
			},
			WantScore: 99,
			WantGrade: "A",
			WantTopDr: "1 warning finding",
		},
		{ // Test 3: Five critical findings on a three-cluster fleet drives score
			// down. Cap on criticals (36) plus version-skew default zero stays under.
			Name: "five criticals",
			In: &Report{
				Clusters: []string{"c1", "c2", "c3"},
				Findings: []Finding{
					{Severity: SeverityCritical},
					{Severity: SeverityCritical},
					{Severity: SeverityCritical},
					{Severity: SeverityCritical},
					{Severity: SeverityCritical},
				},
			},
			WantScore: 70,
			WantGrade: "C",
			WantTopDr: "5 critical findings",
		},
		{ // Test 4: One critical cluster in a fleet of one is 20-point penalty.
			Name: "single critical cluster",
			In: &Report{
				Clusters: []string{"c1"},
				ClusterHealths: []ClusterHealth{
					{Name: "c1", Status: "critical", NodeCount: 3, HealthyNodes: 3},
				},
			},
			WantScore: 80,
			WantGrade: "B",
		},
		{ // Test 5: Worst-case caps add to 76 points; score floor stays above 0.
			// Findings cap at 36, single-cluster-100%-critical adds 20, version
			// skew critical adds 10, all nodes unhealthy adds 10. 100-76=24.
			Name: "all caps applied",
			In: &Report{
				Clusters: []string{"c1", "c2"},
				Findings: makeFindings(SeverityCritical, 200),
				ClusterHealths: []ClusterHealth{
					{Name: "c1", Status: "critical", NodeCount: 10, HealthyNodes: 0,
						KubernetesVersion: "v1.25.0"},
					{Name: "c2", Status: "critical", NodeCount: 10, HealthyNodes: 0,
						KubernetesVersion: "v1.31.0"},
				},
			},
			WantScore: 24,
			WantGrade: "F",
		},
		{ // Test 6: Version skew critical adds 10 points.
			Name: "critical version skew",
			In: &Report{
				Clusters: []string{"c1", "c2", "c3"},
				ClusterHealths: []ClusterHealth{
					{Name: "c1", KubernetesVersion: "v1.31.2", NodeCount: 5, HealthyNodes: 5},
					{Name: "c2", KubernetesVersion: "v1.30.6", NodeCount: 5, HealthyNodes: 5},
					{Name: "c3", KubernetesVersion: "v1.29.10", NodeCount: 5, HealthyNodes: 5},
				},
			},
			WantScore: 90,
			WantGrade: "A",
			WantTopDr: "Kubernetes version skew exceeds one minor",
		},
		{ // Test 7: Worst-node fraction surfaces the worst cluster by name.
			Name: "worst node cluster surfaced",
			In: &Report{
				Clusters: []string{"a", "b"},
				ClusterHealths: []ClusterHealth{
					{Name: "a", NodeCount: 10, HealthyNodes: 10},
					{Name: "b", NodeCount: 10, HealthyNodes: 5},
				},
			},
			WantScore: 95,
			WantGrade: "A",
			WantTopDr: "b has 50% unhealthy nodes",
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := ComputeFleetScore(test.In)
			if got.Score != test.WantScore {
				t.Errorf("score: want %d, got %d", test.WantScore, got.Score)
			}
			if got.Grade != test.WantGrade {
				t.Errorf("grade: want %s, got %s", test.WantGrade, got.Grade)
			}
			if test.WantTopDr != "" {
				if len(got.Drivers) == 0 || got.Drivers[0].Reason != test.WantTopDr {
					t.Errorf("top driver: want %q, got %+v", test.WantTopDr, got.Drivers)
				}
			}
		})
	}
}

func TestComputeFleetScore_Drivers_Sorted(t *testing.T) {
	t.Parallel()
	r := &Report{
		Clusters: []string{"a", "b", "c", "d"},
		Findings: []Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityWarning},
		},
		ClusterHealths: []ClusterHealth{
			{Name: "a", Status: "critical", NodeCount: 3, HealthyNodes: 3},
			{Name: "b", Status: "degraded", NodeCount: 3, HealthyNodes: 3},
			{Name: "c", Status: "healthy", NodeCount: 3, HealthyNodes: 3},
			{Name: "d", Status: "healthy", NodeCount: 3, HealthyNodes: 3},
		},
	}
	got := ComputeFleetScore(r)
	if len(got.Drivers) == 0 {
		t.Fatalf("expected at least one driver, got none")
	}
	for i := 1; i < len(got.Drivers); i++ {
		if got.Drivers[i-1].Impact < got.Drivers[i].Impact {
			t.Errorf("drivers not sorted descending by impact: %+v", got.Drivers)
		}
	}
}

func TestGrade_Boundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		Score int
		Want  string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"}, {79, "C"},
		{70, "C"}, {69, "D"}, {60, "D"}, {59, "F"}, {0, "F"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := grade(c.Score); got != c.Want {
				t.Errorf("grade(%d): want %s, got %s", c.Score, c.Want, got)
			}
		})
	}
}

func TestFleetScore_StructJSON_StableShape(t *testing.T) {
	t.Parallel()
	// Sanity: zero-value FleetScore should compare equal under cmp with EquateEmpty.
	a := FleetScore{}
	b := FleetScore{Drivers: []FleetScoreDriver{}}
	if diff := cmp.Diff(a, b, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("zero-value mismatch (-want +got):\n%s", diff)
	}
}

// makeFindings is a test helper returning n findings of the given severity.
func makeFindings(sev string, n int) []Finding {
	out := make([]Finding, n)
	for i := range out {
		out[i].Severity = sev
	}
	return out
}
