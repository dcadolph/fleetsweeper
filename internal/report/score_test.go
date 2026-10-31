package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// observedBy returns sections in which one OK scanner observed every named cluster, so a
// hand-built report clears the coverage gate.
func observedBy(clusters ...string) map[string]*SectionReport {
	per := make(map[string]any, len(clusters))
	for _, c := range clusters {
		per[c] = map[string]any{"n": 1}
	}
	return map[string]*SectionReport{"s1": {PerCluster: per}}
}

// TestScoreWithAttribution verifies score, grade, and top driver on hand-built reports.
func TestScoreWithAttribution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name      string
		In        *Report
		WantScore int
		WantGrade string
		WantTopDr string
	}{
		{ // Test 0: Nil report scores 100 ungraded with a placeholder headline.
			Name:      "nil report",
			In:        nil,
			WantScore: 100,
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
				Sections: observedBy("c1"),
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
				Sections: observedBy("c1", "c2", "c3"),
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
				Sections: observedBy("c1"),
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
				Sections: observedBy("c1", "c2"),
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
				Sections: observedBy("c1", "c2", "c3"),
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
				Sections: observedBy("a", "b"),
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
				cmpopts.IgnoreFields(FleetScore{}, "Score", "Grade", "Headline", "Drivers", "Graded", "Coverage"),
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
			want := FleetScore{
				Score: test.WantScore, Grade: test.WantGrade, Graded: true, Drivers: test.WantDrivers,
			}
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.IgnoreFields(FleetScore{},
					"Headline", "SampleSize", "Dimensions", "ExcludedClusters", "Coverage"),
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
			fs := FleetScore{Score: test.Score, Graded: true}
			if diff := cmp.Diff(test.WantHeadline, headline(fs, test.Clusters)); diff != "" {
				t.Errorf("headline mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// coverageResults builds per-cluster results for scanners s1 to sN, all OK, then replaces the
// runs named in override, where a missing scanner.Result removes the run.
func coverageResults(
	clusters []string, scanners int, override map[runKey]*scanner.Result,
) map[string]map[string]scanner.Result {
	out := make(map[string]map[string]scanner.Result, len(clusters))
	for _, c := range clusters {
		out[c] = make(map[string]scanner.Result, scanners)
		for i := 1; i <= scanners; i++ {
			name := fmt.Sprintf("s%d", i)
			out[c][name] = okRun(name, map[string]any{"n": 1})
		}
	}
	for k, res := range override {
		if res == nil {
			delete(out[k.cluster], k.scanner)
			continue
		}
		out[k.cluster][k.scanner] = *res
	}
	return out
}

// runOf returns a pointer to res so coverage overrides read as one expression.
func runOf(res scanner.Result) *scanner.Result {
	return &res
}

// TestFleetCoverage verifies the coverage counts and the grading gate on built reports.
func TestFleetCoverage(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()
	two := []string{"c1", "c2"}
	five := []string{"c1", "c2", "c3", "c4", "c5"}
	allErrored := map[runKey]*scanner.Result{}
	for _, c := range two {
		for _, s := range []string{"s1", "s2", "s3"} {
			allErrored[runKey{scanner: s, cluster: c}] = runOf(erroredRun(s))
		}
	}
	tests := []struct {
		Name             string
		Clusters         []string
		Scanners         int
		Override         map[runKey]*scanner.Result
		WantCoverage     FleetCoverage
		WantGraded       bool
		WantGrade        string
		WantHeadlineHead string
	}{{ // Test 0: Every run errored, so nothing is graded and the headline says so.
		Name: "all errored", Clusters: two, Scanners: 3, Override: allErrored,
		WantCoverage:     FleetCoverage{ExpectedRuns: 6, BlindRuns: 6, BlindClusters: 2},
		WantHeadlineHead: "Not enough data: 6 of 6 scanner runs did not observe the fleet",
	}, { // Test 1: Every run OK grades normally with full coverage.
		Name: "all ok", Clusters: two, Scanners: 2,
		WantCoverage:     FleetCoverage{ExpectedRuns: 4, ObservedRuns: 4, Fraction: 1},
		WantGraded:       true,
		WantGrade:        "A",
		WantHeadlineHead: "2 clusters, no meaningful drift.",
	}, { // Test 2: One errored run of ten stays above the floor and grades.
		Name: "one errored of ten", Clusters: two, Scanners: 5,
		Override: map[runKey]*scanner.Result{
			{scanner: "s3", cluster: "c1"}: runOf(erroredRun("s3")),
		},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 10, ObservedRuns: 9, BlindRuns: 1, Fraction: 0.9,
		},
		WantGraded:       true,
		WantGrade:        "A",
		WantHeadlineHead: "2 clusters, nothing flagged in what was observed.",
	}, { // Test 3: Three errored runs of ten fall under the floor.
		Name: "three errored of ten", Clusters: two, Scanners: 5,
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c1"}: runOf(erroredRun("s1")),
			{scanner: "s2", cluster: "c2"}: runOf(erroredRun("s2")),
			{scanner: "s3", cluster: "c1"}: runOf(erroredRun("s3")),
		},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 10, ObservedRuns: 7, BlindRuns: 3, Fraction: 0.7,
		},
		WantHeadlineHead: "Not enough data: 3 of 10 scanner runs did not observe the fleet.",
	}, { // Test 4: A cluster no scanner observed blocks the grade even at the floor.
		Name: "one cluster blind", Clusters: five, Scanners: 2,
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c5"}: runOf(erroredRun("s1")),
			{scanner: "s2", cluster: "c5"}: runOf(erroredRun("s2")),
		},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 10, ObservedRuns: 8, BlindRuns: 2, BlindClusters: 1, Fraction: 0.8,
		},
		WantHeadlineHead: "Not enough data: 2 of 10 scanner runs did not observe the fleet, " +
			"and 1 of 5 clusters had no complete scanner run.",
	}, { // Test 5: Unavailable counts as observed, degraded as neither observed nor blind.
		Name: "unavailable and degraded", Clusters: two, Scanners: 5,
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c1"}: {
				Scanner: "s1", State: scanner.StateUnavailable, Data: map[string]any{"n": 0},
			},
			{scanner: "s2", cluster: "c2"}: runOf(degradedRun("s2", map[string]any{"n": 1})),
		},
		WantCoverage: FleetCoverage{ExpectedRuns: 10, ObservedRuns: 9, Fraction: 0.9},
		WantGraded:   true,
		WantGrade:    "A",
		WantHeadlineHead: "2 clusters, nothing flagged in what was observed. " +
			"1 of 10 scanner runs was partial.",
	}, { // Test 6: A scanner that never ran on a cluster counts as a blind run.
		Name: "absent run", Clusters: two, Scanners: 2,
		Override: map[runKey]*scanner.Result{{scanner: "s2", cluster: "c2"}: nil},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 4, ObservedRuns: 3, BlindRuns: 1, Fraction: 0.75,
		},
		WantHeadlineHead: "Not enough data: 1 of 4 scanner runs did not observe the fleet.",
	}, { // Test 7: Exactly the floor with every cluster observed grades.
		Name: "at the floor", Clusters: five, Scanners: 2,
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c1"}: runOf(erroredRun("s1")),
			{scanner: "s2", cluster: "c2"}: runOf(erroredRun("s2")),
		},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 10, ObservedRuns: 8, BlindRuns: 2, Fraction: 0.8,
		},
		WantGraded: true,
		WantGrade:  "A",
		WantHeadlineHead: "5 clusters, nothing flagged in what was observed. " +
			"2 of 10 scanner runs did not observe the fleet.",
	}, { // Test 8: Clusters with no scanner at all are blind and ungraded.
		Name: "no scanners", Clusters: two, Scanners: 0,
		WantCoverage:     FleetCoverage{BlindClusters: 2},
		WantHeadlineHead: "Not enough data: No scanner ran on 2 listed clusters.",
	}, { // Test 9: Blind and partial runs are both named.
		Name: "blind and partial", Clusters: two, Scanners: 5,
		Override: map[runKey]*scanner.Result{
			{scanner: "s1", cluster: "c1"}: runOf(erroredRun("s1")),
			{scanner: "s2", cluster: "c2"}: runOf(degradedRun("s2", map[string]any{"n": 1})),
		},
		WantCoverage: FleetCoverage{
			ExpectedRuns: 10, ObservedRuns: 8, BlindRuns: 1, Fraction: 0.8,
		},
		WantGraded: true,
		WantGrade:  "A",
		WantHeadlineHead: "2 clusters, nothing flagged in what was observed. " +
			"1 of 10 scanner runs did not observe the fleet and 1 was partial.",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			r := Build(test.Clusters, coverageResults(test.Clusters, test.Scanners, test.Override))
			got := r.FleetScore
			if diff := cmp.Diff(test.WantCoverage, got.Coverage); diff != "" {
				t.Errorf("coverage mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantGraded, got.Graded); diff != "" {
				t.Errorf("graded mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantGrade, got.Grade); diff != "" {
				t.Errorf("grade mismatch (-want +got):\n%s", diff)
			}
			if !strings.HasPrefix(got.Headline, test.WantHeadlineHead) {
				t.Errorf("headline %q, want prefix %q", got.Headline, test.WantHeadlineHead)
			}
			label := fmt.Sprintf(" Observed-only score %d.", got.Score)
			if !got.Graded && !strings.HasSuffix(got.Headline, label) {
				t.Errorf("ungraded headline %q does not label the observed-only score", got.Headline)
			}
			if got.Coverage.BlindRuns > 0 && strings.Contains(got.Headline, "no meaningful drift") {
				t.Errorf("headline %q claims no drift with blind runs", got.Headline)
			}
		})
	}
}

// TestFleetCoverageDecoded verifies a report decoded from JSON yields the coverage Build
// computed, so a stored report rescored after a load grades the same way.
func TestFleetCoverageDecoded(t *testing.T) {
	t.Parallel()
	clusters := []string{"c1", "c2"}
	built := Build(clusters, coverageResults(clusters, 3, map[runKey]*scanner.Result{
		{scanner: "s1", cluster: "c1"}: runOf(erroredRun("s1")),
	}))
	blob, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if diff := cmp.Diff(built.FleetScore.Coverage, fleetCoverage(&decoded)); diff != "" {
		t.Errorf("decoded coverage mismatch (-want +got):\n%s", diff)
	}
}
