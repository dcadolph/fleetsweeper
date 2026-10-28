package report

import (
	"fmt"
	"math"

	"github.com/dcadolph/fleetsweeper/internal/util"
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
	// SampleSize is the number of clusters that contributed scanner data to
	// this score. A score from six clusters and one from sixty are different
	// claims, so the sample travels with the number.
	SampleSize int `json:"sample_size"`
	// Dimensions is the number of scan dimensions that contributed data from
	// at least one cluster.
	Dimensions int `json:"dimensions"`
	// ExcludedClusters is how many scanned clusters contributed no usable data
	// and were left out of the statistical population.
	ExcludedClusters int `json:"excluded_clusters"`
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

// Rescore sets r's fleet score, its attribution, and the summary's finding
// counts from r's current findings and cluster health, so a caller that
// changes findings after Build keeps them in agreement. Safe to call on nil.
func Rescore(r *Report) {
	if r == nil {
		return
	}
	countFindings(&r.Summary, r.Findings)
	var attribution ScoreAttribution
	r.FleetScore, attribution = scoreWithAttribution(r)
	r.ScoreAttribution = &attribution
}

// scoreWithAttribution returns the FleetScore of r and the cost ledger it was
// computed from. The score is 100 minus the ledger's total, rounded and
// floored at zero, and the drivers are the ledger's top three terms.
func scoreWithAttribution(r *Report) (FleetScore, ScoreAttribution) {
	if r == nil {
		return FleetScore{Score: 100, Grade: "A", Headline: "No data yet."}, ScoreAttribution{}
	}
	a := computeScoreAttribution(r)
	raw := math.Max(100.0-a.Total, 0)
	score := int(math.Round(raw))

	sample, dims, excluded := scoreProvenance(r)
	return FleetScore{
		Score:            score,
		Grade:            grade(score),
		Headline:         headline(score, r),
		Drivers:          a.Drivers(),
		SampleSize:       sample,
		Dimensions:       dims,
		ExcludedClusters: excluded,
	}, a
}

// scoreProvenance derives the sample size, contributing dimension count, and
// excluded-cluster count from the report's sections. A cluster contributes when
// at least one scanner returned usable data for it; blind scanner runs never
// enter PerCluster, so a fully blind cluster counts as excluded.
func scoreProvenance(r *Report) (sample, dimensions, excluded int) {
	contributed := make(map[string]struct{}, len(r.Clusters))
	for _, sec := range r.Sections {
		if sec == nil || len(sec.PerCluster) == 0 {
			continue
		}
		dimensions++
		for cluster := range sec.PerCluster {
			contributed[cluster] = struct{}{}
		}
	}
	for _, cluster := range r.Clusters {
		if _, ok := contributed[cluster]; ok {
			sample++
		}
	}
	excluded = len(r.Clusters) - sample
	return sample, dimensions, excluded
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
		return fmt.Sprintf("%d cluster%s, no meaningful drift.", clusters, util.Plural(clusters))
	case score >= 85:
		return fmt.Sprintf("%d cluster%s, light drift worth a glance.", clusters, util.Plural(clusters))
	case score >= 70:
		return fmt.Sprintf("%d cluster%s, real drift to investigate.", clusters, util.Plural(clusters))
	case score >= 50:
		return fmt.Sprintf("%d cluster%s, significant drift across the fleet.", clusters, util.Plural(clusters))
	default:
		return fmt.Sprintf("%d cluster%s, fleet health is degraded.", clusters, util.Plural(clusters))
	}
}
