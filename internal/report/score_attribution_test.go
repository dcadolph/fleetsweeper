package report

import (
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestScoreAttributionLedger checks the ledger term by term on reports whose
// costs are computed by hand.
func TestScoreAttributionLedger(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	warnings := make([]Finding, 0, 30)
	for i := range 30 {
		warnings = append(warnings, Finding{
			Severity: SeverityWarning, Rule: "image-audit/latest-tag", Cluster: fmt.Sprintf("c%d", i%3),
		})
	}

	tests := []struct {
		Report      *Report
		WantTerms   []ScoreTerm
		WantEntries []ScoreEntry
	}{{ // Test 0: Two criticals on one rule and cluster fold into one entry.
		Report: &Report{Findings: []Finding{
			{Severity: SeverityCritical, Rule: "node-health/not-ready", Cluster: "a"},
			{Severity: SeverityCritical, Rule: "node-health/not-ready", Cluster: "a"},
			{Severity: SeverityInfo, Rule: "certs/expiring-30d", Cluster: "b"},
		}},
		WantTerms: []ScoreTerm{
			{Term: TermCriticalFindings, Reason: "2 critical findings", Count: 2, Raw: 12, Cap: 36, Cost: 12},
			{Term: TermInfoFindings, Reason: "1 info finding", Count: 1, Raw: 0.25, Cap: 5, Cost: 0.25},
		},
		WantEntries: []ScoreEntry{
			{Term: TermCriticalFindings, Rule: "node-health/not-ready", Cluster: "a", Raw: 12, Cost: 12},
			{Term: TermInfoFindings, Rule: "certs/expiring-30d", Cluster: "b", Raw: 0.25, Cost: 0.25},
		},
	}, { // Test 1: Thirty warnings cost 45 raw, capped at 24, every entry scaled by 24/45.
		Report: &Report{Findings: warnings},
		WantTerms: []ScoreTerm{
			{Term: TermWarningFindings, Reason: "30 warning findings", Count: 30, Raw: 45, Cap: 24, Cost: 24},
		},
		WantEntries: []ScoreEntry{
			{Term: TermWarningFindings, Rule: "image-audit/latest-tag", Cluster: "c0", Raw: 15, Cost: 8},
			{Term: TermWarningFindings, Rule: "image-audit/latest-tag", Cluster: "c1", Raw: 15, Cost: 8},
			{Term: TermWarningFindings, Rule: "image-audit/latest-tag", Cluster: "c2", Raw: 15, Cost: 8},
		},
	}, { // Test 2: Cluster health, version skew, and the worst node ratio.
		Report: &Report{ClusterHealths: []ClusterHealth{
			{Name: "a", Status: "critical", KubernetesVersion: "v1.31.0", NodeCount: 4, HealthyNodes: 1},
			{Name: "b", Status: "strained", KubernetesVersion: "v1.29.0", NodeCount: 4, HealthyNodes: 4},
			{Name: "c", Status: "healthy", KubernetesVersion: "v1.31.0", NodeCount: 2, HealthyNodes: 1},
			{Name: "d", Status: "degraded", KubernetesVersion: "v1.31.0"},
		}},
		WantTerms: []ScoreTerm{
			{Term: TermCriticalClusters, Reason: "1 of 4 clusters critical", Count: 1, Raw: 5, Cost: 5},
			{Term: TermDegradedClusters, Reason: "2 of 4 clusters degraded", Count: 2, Raw: 5, Cost: 5},
			{Term: TermVersionSkew, Reason: "Kubernetes version skew exceeds one minor", Count: 1, Raw: 10, Cost: 10},
			{Term: TermWorstNode, Reason: "a has 75% unhealthy nodes", Count: 1, Raw: 7.5, Cost: 7.5},
		},
		WantEntries: []ScoreEntry{
			{Term: TermCriticalClusters, Cluster: "a", Raw: 5, Cost: 5},
			{Term: TermDegradedClusters, Cluster: "b", Raw: 2.5, Cost: 2.5},
			{Term: TermDegradedClusters, Cluster: "d", Raw: 2.5, Cost: 2.5},
			{Term: TermVersionSkew, Rule: "version/skew", Raw: 10, Cost: 10},
			{Term: TermWorstNode, Cluster: "a", Raw: 7.5, Cost: 7.5},
		},
	}, { // Test 3: A clean report charges nothing.
		Report: &Report{ClusterHealths: []ClusterHealth{{Name: "a", Status: "healthy", NodeCount: 3, HealthyNodes: 3}}},
	}}
	approx := cmpopts.EquateApprox(0, 1e-9)
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := ComputeScoreAttribution(test.Report)
			if diff := cmp.Diff(test.WantTerms, got.Terms, approx, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("terms mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantEntries, got.Entries, approx, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("entries mismatch (-want +got):\n%s", diff)
			}
			var termSum, entrySum float64
			for _, term := range got.Terms {
				termSum += term.Cost
			}
			for _, e := range got.Entries {
				entrySum += e.Cost
			}
			if math.Abs(termSum-got.Total) > 1e-9 || math.Abs(entrySum-got.Total) > 1e-9 {
				t.Errorf("total %v, terms sum %v, entries sum %v", got.Total, termSum, entrySum)
			}
		})
	}
}

// TestScoreAttributionMatchesScore builds whole reports and checks the ledger
// against the score it explains: costs sum to 100 - Score within rounding, the
// drivers come from the terms, and per-cluster costs sum to the entries.
func TestScoreAttributionMatchesScore(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	reports := []*Report{
		Build(clusters, results, BuildOptions{ClusterTags: tags}),
		Build(makeClusterNames(50), makeSyntheticResults(makeClusterNames(50))),
	}
	for i, r := range reports {
		a := r.ScoreAttribution
		if a == nil {
			t.Fatalf("report %d has no attribution", i)
		}
		if a.Total < 100 && math.Abs(100-a.Total-float64(r.FleetScore.Score)) > 0.5 {
			t.Errorf("report %d: 100 - total %v is not score %d within rounding", i, a.Total, r.FleetScore.Score)
		}
		if diff := cmp.Diff(a.Drivers(), r.FleetScore.Drivers, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("report %d drivers mismatch (-ledger +score):\n%s", i, diff)
		}
		want := map[string]float64{}
		for _, e := range a.Entries {
			if e.Cluster != "" {
				want[e.Cluster] += e.Cost
			}
		}
		if diff := cmp.Diff(want, a.ByCluster, cmpopts.EquateApprox(0, 1e-9), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("report %d by-cluster mismatch (-want +got):\n%s", i, diff)
		}
		if diff := cmp.Diff(ComputeFleetScore(r), r.FleetScore); diff != "" {
			t.Errorf("report %d: ComputeFleetScore disagrees with Build (-compute +build):\n%s", i, diff)
		}
	}
}
