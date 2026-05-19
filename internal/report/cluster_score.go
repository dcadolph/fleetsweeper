package report

import (
	"fmt"
	"math"
)

// ClusterScore is the per-cluster analogue of FleetScore. Same 0-100 scale,
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
// fleet-wide context (use ComputeFleetScore for that); a cluster's own
// findings, status, and node/utilization metrics fully determine the score.
func ComputeClusterScore(h ClusterHealth, findings []Finding) ClusterScore {
	cost := 0.0

	var crit, warn int
	for _, f := range findings {
		if f.Cluster != h.Name && f.Cluster != "" && f.Cluster != "fleet" {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			crit++
		case SeverityWarning:
			warn++
		}
	}
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
		return fmt.Sprintf("Mostly healthy. %d warning%s to triage.", warning, plural(warning))
	case score >= 70:
		return fmt.Sprintf("Drift building. %d critical, %d warning.", critical, warning)
	case score >= 50:
		return fmt.Sprintf("Significant drift. %d critical, %d warning.", critical, warning)
	default:
		return fmt.Sprintf("Degraded. %d critical finding%s.", critical, plural(critical))
	}
}
