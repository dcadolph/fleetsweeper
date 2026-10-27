package report

import (
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// flatOf builds the flattened per-cluster view the detectors read: cluster cNN holds
// vals[NN] under field.
func flatOf(field string, vals ...any) ([]string, map[string]map[string]any) {
	clusters := make([]string, 0, len(vals))
	flat := make(map[string]map[string]any, len(vals))
	for i, v := range vals {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		flat[c] = map[string]any{field: v}
	}
	return clusters, flat
}

// outlierClusters returns the sorted cluster names of outliers.
func outlierClusters(outliers []OutlierResult) []string {
	out := make([]string, 0, len(outliers))
	for _, o := range outliers {
		out = append(out, o.Cluster)
	}
	slices.Sort(out)
	return out
}

func TestDominantStringTie(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Counts     map[string]int
		WantResult string
	}{{ // Test 0: A tie goes to the lexically smallest value.
		Counts: map[string]int{"b": 2, "a": 2, "c": 1}, WantResult: "a",
	}, { // Test 1: The larger count wins over a smaller name.
		Counts: map[string]int{"z": 3, "a": 2}, WantResult: "z",
	}, { // Test 2: An empty map has no mode.
		Counts: map[string]int{}, WantResult: "",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, dominantString(test.Counts)); diff != "" {
				t.Errorf("mode mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStringModeShareBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Vals         []any
		WantClusters []string
		WantShare    float64
	}{{ // Test 0: A mode holding exactly 60% of the fleet flags every other cluster.
		Vals:         []any{"x", "x", "x", "x", "x", "x", "y", "z", "w", "v"},
		WantClusters: []string{"c06", "c07", "c08", "c09"}, WantShare: 0.6,
	}, { // Test 1: A mode at 50% flags nothing.
		Vals:      []any{"x", "x", "x", "x", "x", "y", "z", "w", "v", "u"},
		WantShare: 0.5,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, flat := flatOf("mode", test.Vals...)
			outliers, dist := detectStringOutliers(clusters, flat, "mode", "novel")
			if diff := cmp.Diff(test.WantClusters, outlierClusters(outliers), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("outliers mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantShare, dist.ModeShare); diff != "" {
				t.Errorf("mode share mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSetConsensusCeil(t *testing.T) {
	t.Parallel()
	ab, a := []any{"a", "b"}, []any{"a"}
	tests := []struct {
		Vals          []any
		WantConsensus []string
		WantClusters  []string
	}{{ // Test 0: An item in 4 of 8 clusters is short of ceil(4.8) = 5 and is not consensus.
		Vals:          []any{ab, ab, ab, ab, a, a, a, a},
		WantConsensus: []string{"a"},
	}, { // Test 1: An item in 5 of 8 clusters is consensus and the other three miss it.
		Vals:          []any{ab, ab, ab, ab, ab, a, a, a},
		WantConsensus: []string{"a", "b"}, WantClusters: []string{"c05", "c06", "c07"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, flat := flatOf("items", test.Vals...)
			outliers, dist := detectSetOutliers(clusters, flat, "items", "novel")
			if diff := cmp.Diff(test.WantConsensus, dist.Consensus); diff != "" {
				t.Errorf("consensus mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantClusters, outlierClusters(outliers), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("outliers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMajorityNumericBoundaries(t *testing.T) {
	t.Parallel()
	atThreshold := madScale * (11.0 - 1) / 1
	tests := []struct {
		Vals          []any
		Threshold     float64
		WantCluster   string
		WantDeviation float64
	}{{ // Test 0: A z exactly at the threshold is not an outlier.
		Vals: []any{0, 1, 2, 11}, Threshold: atThreshold,
	}, { // Test 1: A z just over the threshold is, with the exact z as its deviation.
		Vals: []any{0, 1, 2, 11}, Threshold: math.Nextafter(atThreshold, 0),
		WantCluster: "c03", WantDeviation: atThreshold,
	}, { // Test 2: A flat majority reports the capped deviation for the one that differs.
		Vals: []any{5, 5, 5, 9}, Threshold: 3.5,
		WantCluster: "c03", WantDeviation: 1e6,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, flat := flatOf("n", test.Vals...)
			got := majorityNumericOutlier(clusters, flat, "n", test.Threshold)
			if test.WantCluster == "" {
				if got != nil {
					t.Fatalf("want no outlier, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("want an outlier, got none")
			}
			if diff := cmp.Diff(test.WantCluster, got.Cluster); diff != "" {
				t.Errorf("cluster mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDeviation, got.Deviation); diff != "" {
				t.Errorf("deviation mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMajorityDistributionBand(t *testing.T) {
	t.Parallel()
	clusters, flat := flatOf("n", 0, 1, 2, 11)
	dist := majorityNumericDistribution(clusters, flat, "n", 3.5)
	if dist == nil {
		t.Fatal("want a distribution")
	}
	want := Distribution{Median: 1.5, MAD: 1, Band: 3.5 / 0.6745}
	got := Distribution{Median: dist.Median, MAD: dist.MAD, Band: dist.Band}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("distribution mismatch (-want +got):\n%s", diff)
	}
}

func TestBuildThreeClustersRunsMajority(t *testing.T) {
	t.Parallel()
	clusters, results := fieldFleet("novel", "count", 10, 10, 40)
	r := Build(clusters, results)
	if len(r.Notes) != 0 {
		t.Errorf("want no small-fleet note at three clusters, got %v", r.Notes)
	}
	if diff := cmp.Diff([]string{"c02"}, outlierClusters(r.Outliers)); diff != "" {
		t.Errorf("outliers mismatch (-want +got):\n%s", diff)
	}
}

func TestCohortSizeCuts(t *testing.T) {
	t.Parallel()
	vals := []any{10, 10, 40, 20, 22, 24, 24, 24, 26, 26, 80}
	clusters, results := fieldFleet("novel", "count", vals...)
	tags := map[string]string{}
	for i, c := range clusters {
		tags[c] = "core"
		if i < 3 {
			tags[c] = "edge"
		}
	}
	r := Build(clusters, results, BuildOptions{ClusterTags: tags})
	got := map[string][]string{}
	for _, c := range r.Cohorts {
		got[c.Name] = outlierClusters(c.Outliers)
	}
	// Test 0: A cohort of exactly minMajoritySample runs the majority diff.
	// Test 1: A cohort of exactly minMADSample runs MAD.
	want := map[string][]string{"edge": {"c02"}, "core": {"c10"}}
	for name, w := range want {
		if diff := cmp.Diff(w, got[name], cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("cohort %s outliers mismatch (-want +got):\n%s", name, diff)
		}
	}
}

// maxedReport is a report whose score costs sum past 100: every finding cap, both cluster
// health terms, critical version skew, and a fully unhealthy node pool.
func maxedReport() *Report {
	r := &Report{ClusterHealths: []ClusterHealth{
		{Name: "a", Status: "critical", KubernetesVersion: "v1.28.0", NodeCount: 10},
		{Name: "b", Status: "degraded", KubernetesVersion: "v1.31.0", NodeCount: 10, HealthyNodes: 10},
	}}
	add := func(sev string, n int) {
		for i := range n {
			r.Findings = append(r.Findings, Finding{Severity: sev, Cluster: "a", Rule: fmt.Sprintf("%s/%d", sev, i)})
		}
	}
	add(SeverityCritical, 10)
	add(SeverityWarning, 20)
	add(SeverityInfo, 30)
	return r
}

func TestFleetScoreFloorsAtZero(t *testing.T) {
	t.Parallel()
	r := maxedReport()
	a := ComputeScoreAttribution(r)
	// 36 + 24 + 5 finding caps, 10 + 5 health shares of two clusters, 10 skew, 10 nodes.
	if diff := cmp.Diff(100.0, a.Total); diff != "" {
		t.Errorf("total mismatch (-want +got):\n%s", diff)
	}
	r.Findings = append(r.Findings, Finding{Severity: SeverityWarning, Cluster: "b", Rule: "extra"})
	r.ClusterHealths[1].Status = "critical"
	score := ComputeFleetScore(r)
	if diff := cmp.Diff(0, score.Score); diff != "" {
		t.Errorf("score mismatch (-want +got):\n%s", diff)
	}
}

func TestScoreDriversTopThree(t *testing.T) {
	t.Parallel()
	four := &Report{
		ClusterHealths: []ClusterHealth{{Name: "a", Status: "critical"}},
		Findings: []Finding{
			{Severity: SeverityCritical, Cluster: "a", Rule: "c"},
			{Severity: SeverityWarning, Cluster: "a", Rule: "w"},
			{Severity: SeverityInfo, Cluster: "a", Rule: "i"},
		},
	}
	tests := []struct {
		Report      *Report
		WantImpacts []int
	}{{ // Test 0: Seven terms keep the three largest.
		Report: maxedReport(), WantImpacts: []int{36, 24, 10},
	}, { // Test 1: Exactly four terms still keep three.
		Report: four, WantImpacts: []int{20, 6, 2},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			a := ComputeScoreAttribution(test.Report)
			impacts := make([]int, 0, len(a.Terms))
			for _, d := range a.Drivers() {
				impacts = append(impacts, d.Impact)
			}
			if diff := cmp.Diff(test.WantImpacts, impacts); diff != "" {
				t.Errorf("driver impacts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClusterScoreBoundaries(t *testing.T) {
	t.Parallel()
	criticals := make([]Finding, 6)
	for i := range criticals {
		criticals[i] = Finding{Severity: SeverityCritical, Cluster: "c1"}
	}
	tests := []struct {
		Health    ClusterHealth
		Findings  []Finding
		WantScore int
	}{{ // Test 0: Six criticals cost 48 before the cap and 40 after it.
		Health: ClusterHealth{Name: "c1", Status: "healthy"}, Findings: criticals, WantScore: 60,
	}, { // Test 1: CPU exactly at the high-utilization gate is charged.
		Health: ClusterHealth{Name: "c1", Status: "healthy", AvgCPU: 85}, WantScore: 95,
	}, { // Test 2: CPU just under the gate is not.
		Health: ClusterHealth{Name: "c1", Status: "healthy", AvgCPU: 84.9}, WantScore: 100,
	}, { // Test 3: Memory exactly at the gate is charged.
		Health: ClusterHealth{Name: "c1", Status: "healthy", AvgMemory: 85}, WantScore: 95,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := ComputeClusterScore(test.Health, test.Findings)
			if diff := cmp.Diff(test.WantScore, got.Score); diff != "" {
				t.Errorf("score mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
