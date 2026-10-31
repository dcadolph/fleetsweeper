package report

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestComputeClusterScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name      string
		Health    ClusterHealth
		Findings  []Finding
		WantScore int
		WantGrade string
	}{
		{ // Test 0: Healthy cluster, no findings → perfect.
			Name:      "perfect",
			Health:    ClusterHealth{Name: "c1", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			WantScore: 100, WantGrade: "A",
		},
		{ // Test 1: One critical finding on the cluster → -8.
			Name:   "one critical",
			Health: ClusterHealth{Name: "c1", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "c1"},
			},
			WantScore: 92, WantGrade: "A",
		},
		{ // Test 2: Critical status + finding compounds.
			Name:   "critical status and finding",
			Health: ClusterHealth{Name: "c1", Status: "critical", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "c1"},
			},
			WantScore: 72, WantGrade: "C",
		},
		{ // Test 3: Unhealthy nodes pull the score down proportionally.
			// degraded status (-10) + half nodes unhealthy (-7.5) = 17.5; rounds to 83.
			Name:      "half nodes unhealthy",
			Health:    ClusterHealth{Name: "c1", Status: "degraded", NodeCount: 10, HealthyNodes: 5},
			WantScore: 83, WantGrade: "B",
		},
		{ // Test 4: Findings from other clusters are ignored.
			Name:   "other cluster findings ignored",
			Health: ClusterHealth{Name: "c1", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "c2"},
				{Severity: SeverityCritical, Cluster: "c3"},
			},
			WantScore: 100, WantGrade: "A",
		},
		{ // Test 5: Fleet finding without marks costs no cluster.
			Name:   "unmarked fleet finding free",
			Health: ClusterHealth{Name: "c1", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "fleet"},
				{Severity: SeverityWarning, Cluster: ""},
			},
			WantScore: 100, WantGrade: "A",
		},
		{ // Test 6: Fleet finding marks one cluster, only that cluster pays at the mark's severity.
			Name:   "marked cluster pays",
			Health: ClusterHealth{Name: "c1", Status: "degraded", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "fleet", Marks: []ClusterMark{
					{Cluster: "c1", Severity: SeverityWarning},
					{Cluster: "c2", Severity: SeverityCritical},
				}},
			},
			WantScore: 88, WantGrade: "B",
		},
		{ // Test 7: Fleet finding marks another cluster, this one pays nothing.
			Name:   "unmarked cluster free",
			Health: ClusterHealth{Name: "c3", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "fleet", Marks: []ClusterMark{
					{Cluster: "c1", Severity: SeverityWarning},
					{Cluster: "c2", Severity: SeverityCritical},
				}},
			},
			WantScore: 100, WantGrade: "A",
		},
		{ // Test 8: High CPU/Mem util adds 10 (5 each).
			Name:      "high util",
			Health:    ClusterHealth{Name: "c1", Status: "busy", NodeCount: 5, HealthyNodes: 5, AvgCPU: 90, AvgMemory: 90},
			WantScore: 87, WantGrade: "B",
		},
	}
	for testNum, tc := range tests {
		t.Run(fmt.Sprintf("test %d: %s", testNum, tc.Name), func(t *testing.T) {
			t.Parallel()
			got := ComputeClusterScore(tc.Health, tc.Findings)
			if got.Score != tc.WantScore {
				t.Errorf("score: want %d, got %d", tc.WantScore, got.Score)
			}
			if got.Grade != tc.WantGrade {
				t.Errorf("grade: want %s, got %s", tc.WantGrade, got.Grade)
			}
			if got.Cluster != tc.Health.Name {
				t.Errorf("cluster: want %q, got %q", tc.Health.Name, got.Cluster)
			}
		})
	}
}

func TestComputeClusterScores_FromReport(t *testing.T) {
	t.Parallel()
	rpt := &Report{
		Clusters: []string{"a", "b"},
		ClusterHealths: []ClusterHealth{
			{Name: "a", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			{Name: "b", Status: "critical", NodeCount: 5, HealthyNodes: 2},
		},
		Findings: []Finding{
			{Severity: SeverityCritical, Cluster: "b"},
		},
	}
	got := ComputeClusterScores(rpt)
	if len(got) != 2 {
		t.Fatalf("want 2 cluster scores, got %d", len(got))
	}
	var aScore, bScore int
	for _, c := range got {
		switch c.Cluster {
		case "a":
			aScore = c.Score
		case "b":
			bScore = c.Score
		}
	}
	if aScore != 100 {
		t.Errorf("a: want 100, got %d", aScore)
	}
	if bScore >= aScore {
		t.Errorf("b should be lower than a; got %d vs %d", bScore, aScore)
	}
}

func TestComputeClusterScores_NilSafe(t *testing.T) {
	t.Parallel()
	if got := ComputeClusterScores(nil); got != nil {
		t.Errorf("want nil for nil report, got %+v", got)
	}
}

// TestClusterStatusAgreesWithScore builds a report with a version skew finding that marks
// one cluster and asserts every cluster whose status is healthy pays no critical or warning
// charge in its score, and every cluster that pays one is not healthy.
func TestClusterStatusAgreesWithScore(t *testing.T) {
	t.Parallel()
	version := func(v string, minor int) map[string]scanner.Result {
		return map[string]scanner.Result{"version": {Scanner: "version", Data: map[string]any{
			"git_version": v, "minor": minor,
		}}}
	}
	clusters := []string{"a", "b", "c", "d"}
	rpt := Build(clusters, map[string]map[string]scanner.Result{
		"a": version("v1.31.2", 31),
		"b": version("v1.31.2", 31),
		"c": version("v1.31.2", 31),
		"d": version("v1.30.6", 30),
	})
	marked := slices.ContainsFunc(rpt.Findings, func(f Finding) bool {
		return slices.ContainsFunc(f.Marks, func(m ClusterMark) bool { return m.Cluster == "d" })
	})
	if !marked {
		t.Fatalf("want a fleet finding marking d; findings: %+v", rpt.Findings)
	}
	statuses := map[string]string{}
	for _, h := range rpt.ClusterHealths {
		statuses[h.Name] = h.Status
		crit, warn := ClusterCharges(h.Name, rpt.Findings)
		charged := crit+warn > 0
		if (h.Status == "healthy") == charged {
			t.Errorf("%s: status %q but score charges %d critical, %d warning", h.Name, h.Status, crit, warn)
		}
	}
	want := map[string]string{"a": "healthy", "b": "healthy", "c": "healthy", "d": "degraded"}
	if diff := cmp.Diff(want, statuses); diff != "" {
		t.Errorf("statuses mismatch (-want +got):\n%s", diff)
	}
}

// TestComputeClusterScoreUnknown verifies an unknown cluster pays the degraded status cost and
// its headline names the blind runs.
func TestComputeClusterScoreUnknown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Health       ClusterHealth
		WantScore    int
		WantHeadline string
	}{{ // Test 0: One blind run costs the degraded status share.
		Health:       ClusterHealth{Name: "c1", Status: "unknown", BlindScanners: 1},
		WantScore:    90,
		WantHeadline: "Unknown. 1 scanner run did not observe this cluster.",
	}, { // Test 1: Several blind runs are counted in the headline.
		Health:       ClusterHealth{Name: "c1", Status: "unknown", BlindScanners: 24},
		WantScore:    90,
		WantHeadline: "Unknown. 24 scanner runs did not observe this cluster.",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := ComputeClusterScore(test.Health, nil)
			if diff := cmp.Diff(test.WantScore, got.Score); diff != "" {
				t.Errorf("score mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantHeadline, got.Headline); diff != "" {
				t.Errorf("headline mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
