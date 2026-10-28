package report

import (
	"fmt"
	"math"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// ClusterScore is the per-cluster analog of FleetScore. Same 0-100 scale,
// computed from one cluster's findings and health rather than the whole
// fleet. Used for per-cluster forecasts and as a ranking key on the dashboard.
type ClusterScore struct {
	// Cluster is the kubeconfig context name the score applies to.
	Cluster string `json:"cluster"`
	// Score is the 0-100 health score.
	Score int `json:"score"`
	// Grade is the letter grade rollup.
	Grade string `json:"grade"`
	// Headline is a one-line plain-English summary.
	Headline string `json:"headline"`
}

// Per-cluster score weights. Tuned to match FleetScore's intuition: a fleet
// where every cluster scores 80 should itself score around 80.
const (
	clusterScorePerCritical    = 8.0
	clusterScorePerWarning     = 2.0
	clusterScoreCriticalCap    = 40.0
	clusterScoreWarningCap     = 24.0
	clusterScoreCritStatus     = 20.0
	clusterScoreDegradedStatus = 10.0
	clusterScoreBusyStatus     = 3.0
	clusterScoreNodeFracMax    = 15.0
	clusterScoreHighUtil       = 5.0
	clusterScoreHighUtilGate   = 85.0
)

// ComputeClusterScore evaluates one cluster in isolation. It does not consult
// fleet-wide context (the fleet score covers that); a cluster's own
// findings, status, and node/utilization metrics fully determine the score.
func ComputeClusterScore(h ClusterHealth, findings []Finding) ClusterScore {
	cost := 0.0

	crit, warn := ClusterCharges(h.Name, findings)
	cost += math.Min(float64(crit)*clusterScorePerCritical, clusterScoreCriticalCap)
	cost += math.Min(float64(warn)*clusterScorePerWarning, clusterScoreWarningCap)

	switch h.Status {
	case "critical":
		cost += clusterScoreCritStatus
	case "degraded", "strained":
		cost += clusterScoreDegradedStatus
	case "busy":
		cost += clusterScoreBusyStatus
	}

	if h.NodeCount > 0 {
		unhealthy := h.NodeCount - h.HealthyNodes
		if unhealthy > 0 {
			frac := float64(unhealthy) / float64(h.NodeCount)
			cost += clusterScoreNodeFracMax * frac
		}
	}
	if h.AvgCPU >= clusterScoreHighUtilGate {
		cost += clusterScoreHighUtil
	}
	if h.AvgMemory >= clusterScoreHighUtilGate {
		cost += clusterScoreHighUtil
	}

	raw := math.Max(0, 100-cost)
	score := int(math.Round(raw))
	return ClusterScore{
		Cluster:  h.Name,
		Score:    score,
		Grade:    grade(score),
		Headline: clusterHeadline(score, crit, warn),
	}
}

// ClusterCharges counts the critical and warning findings a cluster pays for: its own
// findings at their severity, and each mark a fleet-scoped finding puts on it at the mark's
// severity. A fleet finding with no mark on the cluster costs it nothing. It and
// generateClusterHealth both read clusterSeverityCounts, so score and status never disagree
// about a finding.
func ClusterCharges(cluster string, findings []Finding) (crit, warn int) {
	counts := clusterSeverityCounts(cluster, findings)
	return counts[SeverityCritical], counts[SeverityWarning]
}

// clusterSeverityCounts maps each severity to the number of findings and marks charged to
// the cluster. All three severities are always present.
func clusterSeverityCounts(cluster string, findings []Finding) map[string]int {
	counts := map[string]int{SeverityCritical: 0, SeverityWarning: 0, SeverityInfo: 0}
	count := func(severity string) {
		switch severity {
		case SeverityCritical, SeverityWarning, SeverityInfo:
			counts[severity]++
		}
	}
	for _, f := range findings {
		if f.Cluster == cluster {
			count(f.Severity)
		}
		for _, m := range f.Marks {
			if m.Cluster == cluster {
				count(m.Severity)
			}
		}
	}
	return counts
}

// ComputeClusterScores returns one ClusterScore per cluster in the report.
func ComputeClusterScores(r *Report) []ClusterScore {
	if r == nil {
		return nil
	}
	out := make([]ClusterScore, 0, len(r.ClusterHealths))
	for _, h := range r.ClusterHealths {
		out = append(out, ComputeClusterScore(h, r.Findings))
	}
	return out
}

// clusterHeadline returns a short summary keyed on score band.
func clusterHeadline(score, critical, warning int) string {
	switch {
	case score >= 95:
		return "Healthy. No meaningful drift."
	case score >= 85:
		return fmt.Sprintf("Mostly healthy. %d warning%s to triage.", warning, util.Plural(warning))
	case score >= 70:
		return fmt.Sprintf("Drift building. %d critical, %d warning.", critical, warning)
	case score >= 50:
		return fmt.Sprintf("Significant drift. %d critical, %d warning.", critical, warning)
	default:
		return fmt.Sprintf("Degraded. %d critical finding%s.", critical, util.Plural(critical))
	}
}
