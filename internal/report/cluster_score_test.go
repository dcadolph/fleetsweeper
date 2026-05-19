package report

import (
	"fmt"
	"testing"
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
		{ // Test 5: Fleet-scoped findings count for every cluster.
			Name:   "fleet finding counts",
			Health: ClusterHealth{Name: "c1", Status: "healthy", NodeCount: 5, HealthyNodes: 5},
			Findings: []Finding{
				{Severity: SeverityCritical, Cluster: "fleet"},
			},
			WantScore: 92, WantGrade: "A",
		},
		{ // Test 6: High CPU/Mem util adds 10 (5 each).
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
