package report

import (
	"fmt"
	"math"
	"sort"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// FleetScore is a single 0-100 indicator of overall fleet health, suitable for
// a status-TV hero number on the dashboard. The score is intentionally
// asymmetric: clusters in trouble pull it down faster than warnings do, and
// individual findings are capped so a noisy fleet does not collapse to zero on
// volume alone. The Drivers list names the top reasons the score sits where it
// does so operators can read the number and the explanation in one glance. A
// score resting on too little observed data is not graded: Graded is false, Grade
// is empty, and the headline says how much of the fleet went unobserved.
type FleetScore struct {
	// Score is the rounded 0-100 health score. When Graded is false it is computed from the
	// observed data only and must not be read as the fleet's health.
	Score int `json:"score"`
	// Grade is a single-letter rollup of Score: A 90+, B 80+, C 70+, D 60+, F under 60. Empty
	// when Graded is false.
	Grade string `json:"grade"`
	// Graded is true when coverage clears the floor: every listed cluster has at least one
	// observed scanner run, and at least minCoverageFraction of expected runs are observed.
	Graded bool `json:"graded"`
	// Coverage counts the scanner runs behind the score.
	Coverage FleetCoverage `json:"coverage"`
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

// FleetCoverage counts how many of the scanner runs a report expected actually observed the
// fleet. A run is observed when its state is OK or unavailable, partial when degraded, and blind
// when it errored or never ran on the cluster.
type FleetCoverage struct {
	// ExpectedRuns is the listed clusters times the scanners that ran on at least one cluster.
	ExpectedRuns int `json:"expected_runs"`
	// ObservedRuns is how many expected runs finished OK or found the feature unavailable.
	ObservedRuns int `json:"observed_runs"`
	// BlindRuns is how many expected runs errored or never ran on their cluster.
	BlindRuns int `json:"blind_runs"`
	// BlindClusters is how many listed clusters have no observed run.
	BlindClusters int `json:"blind_clusters"`
	// Fraction is ObservedRuns over ExpectedRuns, zero when no run was expected.
	Fraction float64 `json:"fraction"`
}

// minCoverageFraction is the share of expected scanner runs that must be observed before the
// fleet score is graded.
const minCoverageFraction = 0.8

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
		return FleetScore{Score: 100, Headline: "No data yet."}, ScoreAttribution{}
	}
	a := computeScoreAttribution(r)
	raw := math.Max(100.0-a.Total, 0)
	score := int(math.Round(raw))

	sample, dims, excluded := scoreProvenance(r)
	cov := fleetCoverage(r)
	fs := FleetScore{
		Score:            score,
		Graded:           cov.clearsFloor(),
		Coverage:         cov,
		Drivers:          a.Drivers(),
		SampleSize:       sample,
		Dimensions:       dims,
		ExcludedClusters: excluded,
	}
	if fs.Graded {
		fs.Grade = grade(score)
	}
	fs.Headline = headline(fs, len(r.Clusters))
	return fs, a
}

// fleetCoverage counts r's expected, observed, and blind scanner runs from the run-state
// table.
func fleetCoverage(r *Report) FleetCoverage {
	scanners := expectedScanners(r)
	var c FleetCoverage
	for _, cluster := range r.Clusters {
		observed, blind := clusterRunCounts(r, cluster, scanners)
		c.ExpectedRuns += len(scanners)
		c.ObservedRuns += observed
		c.BlindRuns += blind
		if observed == 0 {
			c.BlindClusters++
		}
	}
	if c.ExpectedRuns > 0 {
		c.Fraction = float64(c.ObservedRuns) / float64(c.ExpectedRuns)
	}
	return c
}

// expectedScanners returns every scanner with a section or a degraded entry in r, so a
// scanner that errored on every cluster is still expected everywhere.
func expectedScanners(r *Report) []string {
	seen := make(map[string]struct{}, len(r.Sections))
	for name := range r.Sections {
		seen[name] = struct{}{}
	}
	for _, d := range r.Degraded {
		seen[d.Scanner] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// clusterRunCounts returns how many of scanners' runs on cluster observed it (OK or
// unavailable) and how many were blind (errored or never ran). Degraded runs are neither.
func clusterRunCounts(r *Report, cluster string, scanners []string) (observed, blind int) {
	for _, name := range scanners {
		st, ok := runState(r, name, cluster)
		switch {
		case !ok || st == scanner.StateErrored:
			blind++
		case st == scanner.StateOK || st == scanner.StateUnavailable:
			observed++
		}
	}
	return observed, blind
}

// clearsFloor reports whether c is enough coverage to grade: no listed cluster went unobserved
// and the observed share is at least minCoverageFraction. A report that expected no runs and
// lists no clusters has nothing missing and clears it.
func (c FleetCoverage) clearsFloor() bool {
	if c.BlindClusters > 0 {
		return false
	}
	return c.ExpectedRuns == 0 || c.Fraction >= minCoverageFraction
}

// partialRuns returns how many expected runs were degraded: neither observed nor blind.
func (c FleetCoverage) partialRuns() int {
	return c.ExpectedRuns - c.ObservedRuns - c.BlindRuns
}

// coverageSentence describes the runs that did not fully observe a fleet of clusters, such as
// "3 of 40 scanner runs did not observe the fleet." It returns "" when every run was observed.
func coverageSentence(c FleetCoverage, clusters int) string {
	partial := c.partialRuns()
	var s string
	switch {
	case c.ExpectedRuns == 0 && c.BlindClusters == 0:
		return ""
	case c.ExpectedRuns == 0:
		return fmt.Sprintf("No scanner ran on %d listed cluster%s.",
			c.BlindClusters, util.Plural(c.BlindClusters))
	case c.BlindRuns > 0 && partial > 0:
		s = fmt.Sprintf("%d of %d scanner runs did not observe the fleet and %d %s partial",
			c.BlindRuns, c.ExpectedRuns, partial, wasWere(partial))
	case c.BlindRuns > 0:
		s = fmt.Sprintf("%d of %d scanner runs did not observe the fleet",
			c.BlindRuns, c.ExpectedRuns)
	case partial > 0:
		s = fmt.Sprintf("%d of %d scanner runs %s partial",
			partial, c.ExpectedRuns, wasWere(partial))
	default:
		return ""
	}
	if c.BlindClusters > 0 {
		s += fmt.Sprintf(", and %d of %d cluster%s had no complete scanner run",
			c.BlindClusters, clusters, util.Plural(clusters))
	}
	return s + "."
}

// wasWere returns the past tense of "to be" agreeing with n.
func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
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
// card on the dashboard. An ungraded score leads with the missing coverage and
// labels the number observed-only. A graded score with unobserved runs names them
// after the band and never claims the fleet is free of drift.
func headline(fs FleetScore, clusters int) string {
	cov := coverageSentence(fs.Coverage, clusters)
	if !fs.Graded {
		return fmt.Sprintf("Not enough data: %s Observed-only score %d.", cov, fs.Score)
	}
	band := scoreBand(fs.Score, clusters, cov != "")
	if cov == "" {
		return band
	}
	return band + " " + cov
}

// scoreBand returns the headline for a graded score of a fleet of clusters. When some runs
// went unobserved the top band says nothing was flagged in what was observed rather than
// claiming no drift.
func scoreBand(score, clusters int, unobserved bool) string {
	switch {
	case score >= 95 && unobserved:
		return fmt.Sprintf("%d cluster%s, nothing flagged in what was observed.",
			clusters, util.Plural(clusters))
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
