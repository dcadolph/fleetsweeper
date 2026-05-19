package report

import (
	"fmt"
	"math"
	"sort"
)

// FleetScore is a single 0-100 indicator of overall fleet health, suitable for
// a status-TV hero number on the dashboard. The score is intentionally
// asymmetric: clusters in trouble pull it down faster than warnings do, and
// individual findings are capped so a noisy fleet does not collapse to zero on
// volume alone. The Drivers list names the top reasons the score sits where it
// does so operators can read the number and the explanation in one glance.
type FleetScore struct {
	// Score is the rounded 0-100 health score.
	Score int `json:"score"`
	// Grade is a single-letter rollup of Score: A 90+, B 80+, C 70+, D 60+, F under 60.
	Grade string `json:"grade"`
	// Headline is a one-line plain-English summary suitable for a hero card.
	Headline string `json:"headline"`
	// Drivers names the top three factors pulling the score below 100, in
	// descending order of impact. Empty when the fleet is at 100.
	Drivers []FleetScoreDriver `json:"drivers,omitempty"`
}

// FleetScoreDriver describes a single factor reducing the fleet score.
type FleetScoreDriver struct {
	// Reason is a short human-readable label.
	Reason string `json:"reason"`
	// Impact is the number of points (whole or fractional, rounded) this
	// driver removed from the score.
	Impact int `json:"impact"`
}

// Score weights. Each constant is the point cost of one occurrence of that
// kind of trouble. Caps prevent a single category from dominating the score:
// a fleet with three hundred warnings and no other issues still scores in the
// 70s, not zero.
const (
	scorePerCritical    = 6.0
	scorePerWarning     = 1.5
	scorePerInfo        = 0.25
	scoreCriticalCap    = 36.0
	scoreWarningCap     = 24.0
	scoreInfoCap        = 5.0
	scoreCriticalFleet  = 20.0
	scoreDegradedFleet  = 10.0
	scoreVersionCritSev = 10.0
	scoreVersionWarnSev = 3.0
	scoreWorstNodeCap   = 10.0
)

// ComputeFleetScore returns a FleetScore derived from a built Report. The
// function is pure: callers can compare scores across scans simply by calling
// it on two different reports. Safe to call on nil; returns a perfect score
// with a placeholder headline.
func ComputeFleetScore(r *Report) FleetScore {
	if r == nil {
		return FleetScore{Score: 100, Grade: "A", Headline: "No data yet."}
	}

	drivers := []FleetScoreDriver{}
	totalCost := 0.0

	if cost, drv := findingCost(r.Findings); cost > 0 {
		totalCost += cost
		drivers = append(drivers, drv...)
	}
	if cost, drv := clusterHealthCost(r.ClusterHealths); cost > 0 {
		totalCost += cost
		drivers = append(drivers, drv...)
	}
	if cost, drv := versionSkewCost(r.ClusterHealths); cost > 0 {
		totalCost += cost
		drivers = append(drivers, drv)
	}
	if cost, drv := worstNodeCost(r.ClusterHealths); cost > 0 {
		totalCost += cost
		drivers = append(drivers, drv)
	}

	raw := 100.0 - totalCost
	if raw < 0 {
		raw = 0
	}
	score := int(math.Round(raw))

	sort.SliceStable(drivers, func(i, j int) bool {
		return drivers[i].Impact > drivers[j].Impact
	})
	if len(drivers) > 3 {
		drivers = drivers[:3]
	}

	return FleetScore{
		Score:    score,
		Grade:    grade(score),
		Headline: headline(score, r),
		Drivers:  drivers,
	}
}

// findingCost returns the total points subtracted by findings plus a
// per-severity driver entry for each non-zero severity.
func findingCost(findings []Finding) (float64, []FleetScoreDriver) {
	var crit, warn, info int
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			crit++
		case SeverityWarning:
			warn++
		case SeverityInfo:
			info++
		}
	}

	critCost := math.Min(float64(crit)*scorePerCritical, scoreCriticalCap)
	warnCost := math.Min(float64(warn)*scorePerWarning, scoreWarningCap)
	infoCost := math.Min(float64(info)*scorePerInfo, scoreInfoCap)
	total := critCost + warnCost + infoCost

	var drivers []FleetScoreDriver
	if critCost > 0 {
		drivers = append(drivers, FleetScoreDriver{
			Reason: fmt.Sprintf("%d critical finding%s", crit, plural(crit)),
			Impact: int(math.Round(critCost)),
		})
	}
	if warnCost > 0 {
		drivers = append(drivers, FleetScoreDriver{
			Reason: fmt.Sprintf("%d warning finding%s", warn, plural(warn)),
			Impact: int(math.Round(warnCost)),
		})
	}
	if infoCost > 0 {
		drivers = append(drivers, FleetScoreDriver{
			Reason: fmt.Sprintf("%d info finding%s", info, plural(info)),
			Impact: int(math.Round(infoCost)),
		})
	}
	return total, drivers
}

// clusterHealthCost penalises fleets where a meaningful fraction of clusters
// are not healthy. Scaling by fraction-of-fleet keeps the cost proportional:
// one critical cluster in a fleet of three hurts more than one critical
// cluster in a fleet of thirty.
func clusterHealthCost(healths []ClusterHealth) (float64, []FleetScoreDriver) {
	if len(healths) == 0 {
		return 0, nil
	}
	var crit, deg int
	for _, h := range healths {
		switch h.Status {
		case "critical":
			crit++
		case "degraded", "strained":
			deg++
		}
	}
	total := len(healths)
	critCost := scoreCriticalFleet * float64(crit) / float64(total)
	degCost := scoreDegradedFleet * float64(deg) / float64(total)

	var drivers []FleetScoreDriver
	if critCost > 0 {
		drivers = append(drivers, FleetScoreDriver{
			Reason: fmt.Sprintf("%d of %d cluster%s critical", crit, total, plural(total)),
			Impact: int(math.Round(critCost)),
		})
	}
	if degCost > 0 {
		drivers = append(drivers, FleetScoreDriver{
			Reason: fmt.Sprintf("%d of %d cluster%s degraded", deg, total, plural(total)),
			Impact: int(math.Round(degCost)),
		})
	}
	return critCost + degCost, drivers
}

// versionSkewCost charges for Kubernetes version skew across the fleet using
// the same severity calibration as the existing VersionSkewSeverity rule.
func versionSkewCost(healths []ClusterHealth) (float64, FleetScoreDriver) {
	if len(healths) < 2 {
		return 0, FleetScoreDriver{}
	}
	versions := make([]string, 0, len(healths))
	for _, h := range healths {
		if h.KubernetesVersion != "" {
			versions = append(versions, h.KubernetesVersion)
		}
	}
	sev := VersionSkewSeverity(versions)
	switch sev {
	case SeverityCritical:
		return scoreVersionCritSev, FleetScoreDriver{
			Reason: "Kubernetes version skew exceeds one minor",
			Impact: int(scoreVersionCritSev),
		}
	case SeverityWarning:
		return scoreVersionWarnSev, FleetScoreDriver{
			Reason: "Kubernetes version skew across the fleet",
			Impact: int(scoreVersionWarnSev),
		}
	}
	return 0, FleetScoreDriver{}
}

// worstNodeCost penalises the fleet according to the cluster with the worst
// unhealthy-node ratio. We take the worst rather than the average so a single
// cluster melting down does not get hidden by a healthy long tail.
func worstNodeCost(healths []ClusterHealth) (float64, FleetScoreDriver) {
	var worstFrac float64
	var worstCluster string
	for _, h := range healths {
		if h.NodeCount <= 0 {
			continue
		}
		unhealthy := h.NodeCount - h.HealthyNodes
		if unhealthy <= 0 {
			continue
		}
		frac := float64(unhealthy) / float64(h.NodeCount)
		if frac > worstFrac {
			worstFrac = frac
			worstCluster = h.Name
		}
	}
	if worstFrac == 0 {
		return 0, FleetScoreDriver{}
	}
	cost := scoreWorstNodeCap * worstFrac
	return cost, FleetScoreDriver{
		Reason: fmt.Sprintf("%s has %d%% unhealthy nodes", worstCluster, int(math.Round(worstFrac*100))),
		Impact: int(math.Round(cost)),
	}
}

// grade maps a numeric score to a letter grade.
func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// headline returns a one-line plain-English summary suitable for the hero
// card on the dashboard.
func headline(score int, r *Report) string {
	clusters := len(r.Clusters)
	switch {
	case score >= 95:
		return fmt.Sprintf("%d cluster%s, no meaningful drift.", clusters, plural(clusters))
	case score >= 85:
		return fmt.Sprintf("%d cluster%s, light drift worth a glance.", clusters, plural(clusters))
	case score >= 70:
		return fmt.Sprintf("%d cluster%s, real drift to investigate.", clusters, plural(clusters))
	case score >= 50:
		return fmt.Sprintf("%d cluster%s, significant drift across the fleet.", clusters, plural(clusters))
	default:
		return fmt.Sprintf("%d cluster%s, fleet health is degraded.", clusters, plural(clusters))
	}
}

// plural returns "s" when n is not 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
