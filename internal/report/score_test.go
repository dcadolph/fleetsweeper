package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestScoreWithAttribution(t *testing.T) {
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
			got, _ := scoreWithAttribution(test.In)
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

func TestFleetScoreDriversSorted(t *testing.T) {
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
	got, _ := scoreWithAttribution(r)
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

func TestFleetScoreProvenance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name         string
		In           *Report
		WantSample   int
		WantDims     int
		WantExcluded int
	}{
		{ // Test 0: Nil report carries zero provenance.
			Name: "nil report",
			In:   nil,
		},
		{ // Test 1: Clusters listed but no sections means nothing contributed.
			Name:         "no sections",
			In:           &Report{Clusters: []string{"c1", "c2"}},
			WantExcluded: 2,
		},
		{ // Test 2: Every cluster contributes to every section.
			Name: "full coverage",
			In: &Report{
				Clusters: []string{"c1", "c2"},
				Sections: map[string]*SectionReport{
					"version":     {PerCluster: map[string]any{"c1": "v1", "c2": "v1"}},
					"node-health": {PerCluster: map[string]any{"c1": 1, "c2": 2}},
				},
			},
			WantSample: 2,
			WantDims:   2,
		},
		{ // Test 3: A cluster with no usable data in any section is excluded.
			Name: "one cluster fully blind",
			In: &Report{
				Clusters: []string{"c1", "c2", "c3"},
				Sections: map[string]*SectionReport{
					"version":     {PerCluster: map[string]any{"c1": "v1", "c2": "v1"}},
					"node-health": {PerCluster: map[string]any{"c1": 1}},
				},
			},
			WantSample:   2,
			WantDims:     2,
			WantExcluded: 1,
		},
		{ // Test 4: Empty and nil sections do not count as dimensions.
			Name: "empty sections skipped",
			In: &Report{
				Clusters: []string{"c1"},
				Sections: map[string]*SectionReport{
					"version": {PerCluster: map[string]any{"c1": "v1"}},
					"events":  {PerCluster: map[string]any{}},
					"metrics": nil,
				},
			},
			WantSample: 1,
			WantDims:   1,
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, _ := scoreWithAttribution(test.In)
			want := FleetScore{
				SampleSize:       test.WantSample,
				Dimensions:       test.WantDims,
				ExcludedClusters: test.WantExcluded,
			}
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.IgnoreFields(FleetScore{}, "Score", "Grade", "Headline", "Drivers"),
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("provenance mismatch (-want +got):\n%s", diff)
			}
		})
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

// TestFleetScoreGolden pins each weight, cap, and rounding rule with
// expectations computed by hand from the constants in score.go.
func TestFleetScoreGolden(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	flat := func(names ...string) []ClusterHealth {
		out := make([]ClusterHealth, len(names))
		for i, n := range names {
			out[i] = ClusterHealth{Name: n}
		}
		return out
	}
	withStatus := func(healths []ClusterHealth, status ...string) []ClusterHealth {
		for i, s := range status {
			healths[i].Status = s
		}
		return healths
	}

	tests := []struct {
		Name        string
		In          *Report
		WantScore   int
		WantGrade   string
		WantDrivers []FleetScoreDriver
	}{{ // Test 0: 4 warnings cost 4*1.5=6, so 100-6=94.
		Name:        "warnings under cap",
		In:          &Report{Findings: makeFindings(SeverityWarning, 4)},
		WantScore:   94,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "4 warning findings", Impact: 6}},
	}, { // Test 1: 30 warnings cost 30*1.5=45, capped at 24, so 100-24=76.
		Name:        "warning cap",
		In:          &Report{Findings: makeFindings(SeverityWarning, 30)},
		WantScore:   76,
		WantGrade:   "C",
		WantDrivers: []FleetScoreDriver{{Reason: "30 warning findings", Impact: 24}},
	}, { // Test 2: 8 infos cost 8*0.25=2, so 100-2=98.
		Name:        "infos under cap",
		In:          &Report{Findings: makeFindings(SeverityInfo, 8)},
		WantScore:   98,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "8 info findings", Impact: 2}},
	}, { // Test 3: 40 infos cost 40*0.25=10, capped at 5, so 100-5=95.
		Name:        "info cap",
		In:          &Report{Findings: makeFindings(SeverityInfo, 40)},
		WantScore:   95,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "40 info findings", Impact: 5}},
	}, { // Test 4: One degraded of four costs 10*1/4=2.5, 97.5 rounds to 98, impact rounds to 3.
		Name:        "one degraded of four",
		In:          &Report{ClusterHealths: withStatus(flat("a", "b", "c", "d"), "degraded")},
		WantScore:   98,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "1 of 4 clusters degraded", Impact: 3}},
	}, { // Test 5: Strained counts as degraded, 10*1/4=2.5, so 98.
		Name:        "strained counts as degraded",
		In:          &Report{ClusterHealths: withStatus(flat("a", "b", "c", "d"), "strained")},
		WantScore:   98,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "1 of 4 clusters degraded", Impact: 3}},
	}, { // Test 6: Minors 30 and 31 differ by one, a warning skew costing 3, so 97.
		Name: "one minor skew",
		In: &Report{ClusterHealths: []ClusterHealth{
			{Name: "a", KubernetesVersion: "v1.30.1"},
			{Name: "b", KubernetesVersion: "v1.31.0"},
		}},
		WantScore:   97,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "Kubernetes version skew across the fleet", Impact: 3}},
	}, { // Test 7: Minors 29 and 31 differ by two, a critical skew costing 10, so 90.
		Name: "two minor skew",
		In: &Report{ClusterHealths: []ClusterHealth{
			{Name: "a", KubernetesVersion: "v1.29.0"},
			{Name: "b", KubernetesVersion: "v1.31.0"},
		}},
		WantScore:   90,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "Kubernetes version skew exceeds one minor", Impact: 10}},
	}, { // Test 8: Patch-only differences cost nothing, so 100.
		Name: "patch only skew",
		In: &Report{ClusterHealths: []ClusterHealth{
			{Name: "a", KubernetesVersion: "v1.31.1"},
			{Name: "b", KubernetesVersion: "v1.31.2"},
		}},
		WantScore: 100,
		WantGrade: "A",
	}, { // Test 9: Unhealthy ratios 0.1, 0.3, 0.5; only the worst counts, 10*0.5=5, so 95.
		// An average would cost 10*0.3=3 and score 97.
		Name: "worst node ratio only",
		In: &Report{ClusterHealths: []ClusterHealth{
			{Name: "a", NodeCount: 10, HealthyNodes: 9},
			{Name: "b", NodeCount: 10, HealthyNodes: 7},
			{Name: "c", NodeCount: 4, HealthyNodes: 2},
		}},
		WantScore:   95,
		WantGrade:   "A",
		WantDrivers: []FleetScoreDriver{{Reason: "c has 50% unhealthy nodes", Impact: 5}},
	}, { // Test 10: Five drivers keep the top three. Costs: 2 crit 12, 4 warn 6, 4 info 1,
		// 1 of 4 critical 20/4=5, 1 of 4 degraded 10/4=2.5. Total 26.5, 73.5 rounds to 74.
		Name: "five drivers truncated to three",
		In: &Report{
			Findings: append(append(makeFindings(SeverityCritical, 2),
				makeFindings(SeverityWarning, 4)...), makeFindings(SeverityInfo, 4)...),
			ClusterHealths: withStatus(flat("a", "b", "c", "d"), "critical", "degraded"),
		},
		WantScore: 74,
		WantGrade: "C",
		WantDrivers: []FleetScoreDriver{
			{Reason: "2 critical findings", Impact: 12},
			{Reason: "4 warning findings", Impact: 6},
			{Reason: "1 of 4 clusters critical", Impact: 5},
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, _ := scoreWithAttribution(test.In)
			want := FleetScore{Score: test.WantScore, Grade: test.WantGrade, Drivers: test.WantDrivers}
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.IgnoreFields(FleetScore{}, "Headline", "SampleSize", "Dimensions", "ExcludedClusters"),
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("score mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHeadlineThresholds pins the headline bands at 95, 85, 70, and 50.
func TestHeadlineThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Score        int
		Clusters     int
		WantHeadline string
	}{
		{Score: 100, Clusters: 3, WantHeadline: "3 clusters, no meaningful drift."},               // Test 0: Score 100.
		{Score: 95, Clusters: 1, WantHeadline: "1 cluster, no meaningful drift."},                 // Test 1: Score 95.
		{Score: 94, Clusters: 3, WantHeadline: "3 clusters, light drift worth a glance."},         // Test 2: Score 94.
		{Score: 85, Clusters: 3, WantHeadline: "3 clusters, light drift worth a glance."},         // Test 3: Score 85.
		{Score: 84, Clusters: 3, WantHeadline: "3 clusters, real drift to investigate."},          // Test 4: Score 84.
		{Score: 70, Clusters: 3, WantHeadline: "3 clusters, real drift to investigate."},          // Test 5: Score 70.
		{Score: 69, Clusters: 3, WantHeadline: "3 clusters, significant drift across the fleet."}, // Test 6: Score 69.
		{Score: 50, Clusters: 3, WantHeadline: "3 clusters, significant drift across the fleet."}, // Test 7: Score 50.
		{Score: 49, Clusters: 3, WantHeadline: "3 clusters, fleet health is degraded."},           // Test 8: Score 49.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := &Report{Clusters: make([]string, test.Clusters)}
			if diff := cmp.Diff(test.WantHeadline, headline(test.Score, r)); diff != "" {
				t.Errorf("headline mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
