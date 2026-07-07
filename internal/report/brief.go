package report

import "fmt"

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
			"Fleet score %d (%s). %d clusters, %d critical and %d warning findings across %d incidents.",
			r.FleetScore.Score, r.FleetScore.Grade, len(r.Clusters), crit, warn, len(r.Incidents),
		),
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
