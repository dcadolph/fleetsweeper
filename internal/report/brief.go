package report

import (
	"fmt"
	"math"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Brief is a short, deterministic executive summary of a fleet report, suitable
// for the top of a dashboard or a status email. It is templated from the report
// with no randomness, so the same scan always yields the same words.
type Brief struct {
	// Headline is the one-line status.
	Headline string `json:"headline"`
	// Lines are the supporting summary points, most important first.
	Lines []string `json:"lines,omitempty"`
}

// GenerateBrief synthesizes an executive summary from a fully built report: the
// score, the worst incident, cohort drift, degraded coverage, and the fixes
// that matter most.
func GenerateBrief(r *Report) Brief {
	crit := countFindingsBySeverity(r.Findings, SeverityCritical)
	warn := countFindingsBySeverity(r.Findings, SeverityWarning)

	b := Brief{
		Headline: fmt.Sprintf(
			"Fleet score %d (%s) from %d clusters across %d dimensions. "+
				"%d critical and %d warning findings across %d incidents.",
			r.FleetScore.Score, r.FleetScore.Grade, r.FleetScore.SampleSize,
			r.FleetScore.Dimensions, crit, warn, len(r.Incidents),
		),
	}

	if line := normLine(r.Findings); line != "" {
		b.Lines = append(b.Lines, line)
	}

	if r.FleetScore.ExcludedClusters > 0 {
		b.Lines = append(b.Lines, fmt.Sprintf(
			"%d cluster(s) excluded from the score for insufficient data.",
			r.FleetScore.ExcludedClusters,
		))
	}

	if len(r.Incidents) > 0 {
		b.Lines = append(b.Lines, "Worst incident: "+r.Incidents[0].Title+".")
	}

	var cohortOutliers int
	for _, c := range r.Cohorts {
		cohortOutliers += len(c.Outliers)
	}
	if cohortOutliers > 0 {
		b.Lines = append(b.Lines, fmt.Sprintf("%d cluster metric(s) drifted from their cohort baseline.", cohortOutliers))
	}

	if len(r.Degraded) > 0 {
		b.Lines = append(b.Lines, fmt.Sprintf(
			"Coverage is partial: %d scanner run(s) degraded on %d cluster(s).",
			len(r.Degraded), len(r.DegradedByCluster()),
		))
	}

	for _, fix := range topFixes(r.Findings, 2) {
		b.Lines = append(b.Lines, "Fix: "+fix)
	}

	if len(r.Findings) == 0 {
		b.Lines = append(b.Lines, "No findings. The fleet is consistent.")
	}

	return b
}

// normLine quotes the norm behind the most severe fleet-relative finding, the
// one with the largest deviation among equals, e.g. "edge-nyc-42
// enforced_count is 30 vs a fleet median of 12 across 26 clusters". It returns
// "" when no finding carries a norm.
func normLine(findings []Finding) string {
	var best *Finding
	for i := range findings {
		f := &findings[i]
		if f.Norm == nil {
			continue
		}
		if best == nil || util.SeverityRank(f.Severity) > util.SeverityRank(best.Severity) ||
			(f.Severity == best.Severity && math.Abs(f.Norm.Z) > math.Abs(best.Norm.Z)) {
			best = f
		}
	}
	if best == nil {
		return ""
	}
	n := best.Norm
	field := best.Rule
	if len(best.Affected) > 0 {
		field = best.Affected[0]
	}
	scope := "a fleet"
	if n.Scope != NormScopeFleet {
		scope = fmt.Sprintf("the cohort %q", n.Scope)
	}
	switch n.Kind {
	case NormKindNumeric:
		return fmt.Sprintf("Largest deviation: %s %s is %s vs %s median of %s across %d clusters.",
			best.Cluster, field, n.Value, scope, formatNum(n.Median), n.SampleSize)
	case NormKindString:
		return fmt.Sprintf("Largest deviation: %s %s is %q vs %s mode of %q held by %.0f%% of %d clusters.",
			best.Cluster, field, n.Value, scope, n.Mode, n.ModeShare*100, n.SampleSize)
	case NormKindSet:
		return fmt.Sprintf("Largest deviation: %s %s lacks %d of the %d members %s holds in common across %d clusters.",
			best.Cluster, field, len(n.Missing), len(n.Consensus), scopeNoun(n.Scope), n.SampleSize)
	}
	return ""
}

// scopeNoun names a norm scope as the subject of a sentence.
func scopeNoun(scope string) string {
	if scope == NormScopeFleet {
		return "the fleet"
	}
	return fmt.Sprintf("cohort %q", scope)
}

// countFindingsBySeverity tallies findings of a given severity.
func countFindingsBySeverity(findings []Finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// topFixes returns up to n actionable findings, critical and warning only,
// preferring the ones that carry a remediation command. Findings arrive sorted
// with the most severe first, so this surfaces the fixes that matter most.
func topFixes(findings []Finding, n int) []string {
	var out []string
	for _, f := range findings {
		if f.Severity == SeverityInfo {
			continue
		}
		fix := f.Title
		if f.Remediation != nil && f.Remediation.Command != "" {
			fix += " (" + f.Remediation.Command + ")"
		}
		out = append(out, fix)
		if len(out) >= n {
			break
		}
	}
	return out
}
