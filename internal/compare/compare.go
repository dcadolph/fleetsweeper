// Package compare produces a structured diff between two Fleetsweeper
// reports: what changed in the Fleet Score, which findings are new, which
// resolved, which persisted, and how cluster statuses moved.
//
// The diff is the unit of operator review: "what changed since the deploy"
// or "what got fixed in the last hour". Each renderer (text, json,
// markdown) wraps the same ScanDiff so reports can be embedded in tickets,
// chat, or CI pipelines without re-deriving anything.
package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// ScanDiff captures every meaningful change between two reports. The "old"
// (A) report is the reference; the "new" (B) report is what we compare it
// to. All fields are populated even when empty so renderers can show
// "0 new findings" rather than failing on a nil deref.
type ScanDiff struct {
	// ScoreBefore is the Fleet Score from A.
	ScoreBefore int `json:"score_before"`
	// ScoreAfter is the Fleet Score from B.
	ScoreAfter int `json:"score_after"`
	// GradeBefore is the grade from A.
	GradeBefore string `json:"grade_before"`
	// GradeAfter is the grade from B.
	GradeAfter string `json:"grade_after"`
	// New are findings present in B but not in A.
	New []report.Finding `json:"new"`
	// Resolved are findings present in A but not in B.
	Resolved []report.Finding `json:"resolved"`
	// Persisted are findings present in both reports.
	Persisted []report.Finding `json:"persisted"`
	// ClusterStatusChanges lists clusters whose health status moved.
	ClusterStatusChanges []ClusterStatusChange `json:"cluster_status_changes"`
	// AddedClusters are clusters present in B but not in A.
	AddedClusters []string `json:"added_clusters"`
	// RemovedClusters are clusters present in A but not in B.
	RemovedClusters []string `json:"removed_clusters"`
	// CriticalBefore is the count of critical findings in A.
	CriticalBefore int `json:"critical_before"`
	// CriticalAfter is the count of critical findings in B.
	CriticalAfter int `json:"critical_after"`
	// WarningBefore is the count of warning findings in A.
	WarningBefore int `json:"warning_before"`
	// WarningAfter is the count of warning findings in B.
	WarningAfter int `json:"warning_after"`
}

// ClusterStatusChange captures one cluster's health-status transition.
type ClusterStatusChange struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// Before is the status in A.
	Before string `json:"before"`
	// After is the status in B.
	After string `json:"after"`
}

// Diff returns the change set going from a (older) to b (newer). Either
// argument may be nil, in which case the missing report is treated as an
// empty fleet (useful for "first scan" comparisons).
func Diff(a, b *report.Report) ScanDiff {
	out := ScanDiff{}
	out.populateScore(a, b)
	out.populateFindings(a, b)
	out.populateClusters(a, b)
	out.populateSummary(a, b)
	return out
}

// populateScore sets the Fleet Score before/after on the diff.
func (d *ScanDiff) populateScore(a, b *report.Report) {
	if a != nil {
		d.ScoreBefore = a.FleetScore.Score
		d.GradeBefore = a.FleetScore.Grade
	}
	if b != nil {
		d.ScoreAfter = b.FleetScore.Score
		d.GradeAfter = b.FleetScore.Grade
	}
}

// populateFindings categorises every finding in A and B into New, Resolved,
// or Persisted. Identity is fingerprint (cluster+scanner+title) so wording
// tweaks to descriptions do not flip a persisted finding into resolved+new.
func (d *ScanDiff) populateFindings(a, b *report.Report) {
	keyOf := func(f report.Finding) string {
		return f.Cluster + "\x00" + f.Scanner + "\x00" + f.Title
	}

	aIdx := map[string]report.Finding{}
	bIdx := map[string]report.Finding{}
	if a != nil {
		for _, f := range a.Findings {
			aIdx[keyOf(f)] = f
		}
	}
	if b != nil {
		for _, f := range b.Findings {
			bIdx[keyOf(f)] = f
		}
	}

	for k, f := range bIdx {
		if _, ok := aIdx[k]; ok {
			d.Persisted = append(d.Persisted, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for k, f := range aIdx {
		if _, ok := bIdx[k]; !ok {
			d.Resolved = append(d.Resolved, f)
		}
	}
	sort.Slice(d.New, lessBySeverityThenTitle(d.New))
	sort.Slice(d.Resolved, lessBySeverityThenTitle(d.Resolved))
	sort.Slice(d.Persisted, lessBySeverityThenTitle(d.Persisted))
}

// populateClusters records cluster additions, removals, and status moves.
func (d *ScanDiff) populateClusters(a, b *report.Report) {
	aHealth := map[string]string{}
	bHealth := map[string]string{}
	if a != nil {
		for _, h := range a.ClusterHealths {
			aHealth[h.Name] = h.Status
		}
	}
	if b != nil {
		for _, h := range b.ClusterHealths {
			bHealth[h.Name] = h.Status
		}
	}
	for name, after := range bHealth {
		before, hadBefore := aHealth[name]
		if !hadBefore {
			d.AddedClusters = append(d.AddedClusters, name)
			continue
		}
		if before != after {
			d.ClusterStatusChanges = append(d.ClusterStatusChanges,
				ClusterStatusChange{Cluster: name, Before: before, After: after})
		}
	}
	for name := range aHealth {
		if _, ok := bHealth[name]; !ok {
			d.RemovedClusters = append(d.RemovedClusters, name)
		}
	}
	sort.Strings(d.AddedClusters)
	sort.Strings(d.RemovedClusters)
	sort.Slice(d.ClusterStatusChanges, func(i, j int) bool {
		return d.ClusterStatusChanges[i].Cluster < d.ClusterStatusChanges[j].Cluster
	})
}

// populateSummary records per-severity totals so renderers can show
// before/after pairs without rescanning findings.
func (d *ScanDiff) populateSummary(a, b *report.Report) {
	if a != nil {
		d.CriticalBefore = a.Summary.CriticalCount
		d.WarningBefore = a.Summary.WarningCount
	}
	if b != nil {
		d.CriticalAfter = b.Summary.CriticalCount
		d.WarningAfter = b.Summary.WarningCount
	}
}

// lessBySeverityThenTitle is a sort comparator for finding slices: critical
// before warning before info, ties broken by cluster name + title.
func lessBySeverityThenTitle(fs []report.Finding) func(i, j int) bool {
	order := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityWarning:  1,
		report.SeverityInfo:     2,
	}
	return func(i, j int) bool {
		oi, oj := order[fs[i].Severity], order[fs[j].Severity]
		if oi != oj {
			return oi < oj
		}
		if fs[i].Cluster != fs[j].Cluster {
			return fs[i].Cluster < fs[j].Cluster
		}
		return fs[i].Title < fs[j].Title
	}
}

// RenderText returns a plain-text rendering of the diff suitable for the
// terminal. When color is true severities and deltas get ANSI codes.
func RenderText(d ScanDiff, color bool) string {
	red := wrap("31", color)
	green := wrap("32", color)
	yellow := wrap("33", color)
	dim := wrap("90", color)
	reset := func() string {
		if !color {
			return ""
		}
		return "\033[0m"
	}

	var b strings.Builder
	delta := d.ScoreAfter - d.ScoreBefore
	deltaStr := fmt.Sprintf("%+d", delta)
	switch {
	case delta < 0:
		deltaStr = red + deltaStr + reset()
	case delta > 0:
		deltaStr = green + deltaStr + reset()
	default:
		deltaStr = dim + deltaStr + reset()
	}

	fmt.Fprintf(&b, "Fleet Score:  %d (%s) -> %d (%s)  (%s)\n",
		d.ScoreBefore, d.GradeBefore, d.ScoreAfter, d.GradeAfter, deltaStr)
	fmt.Fprintf(&b, "Critical:     %d -> %d\n", d.CriticalBefore, d.CriticalAfter)
	fmt.Fprintf(&b, "Warning:      %d -> %d\n", d.WarningBefore, d.WarningAfter)
	fmt.Fprintln(&b)

	renderFindingsSection(&b, "NEW", d.New, red, reset())
	renderFindingsSection(&b, "RESOLVED", d.Resolved, green, reset())

	if len(d.ClusterStatusChanges) > 0 {
		fmt.Fprintf(&b, "%sCluster status changes:%s\n", yellow, reset())
		for _, c := range d.ClusterStatusChanges {
			fmt.Fprintf(&b, "  %s: %s -> %s\n", c.Cluster, c.Before, c.After)
		}
		fmt.Fprintln(&b)
	}
	if len(d.AddedClusters) > 0 {
		fmt.Fprintf(&b, "Added clusters (%d):\n", len(d.AddedClusters))
		for _, c := range d.AddedClusters {
			fmt.Fprintf(&b, "  + %s\n", c)
		}
		fmt.Fprintln(&b)
	}
	if len(d.RemovedClusters) > 0 {
		fmt.Fprintf(&b, "Removed clusters (%d):\n", len(d.RemovedClusters))
		for _, c := range d.RemovedClusters {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
		fmt.Fprintln(&b)
	}
	if len(d.Persisted) > 0 {
		fmt.Fprintf(&b, "%s%d findings persisted across both scans.%s\n",
			dim, len(d.Persisted), reset())
	}
	return b.String()
}

// renderFindingsSection writes a labelled list of findings to b. Empty
// sections render a one-line "(none)" instead of being skipped, so the
// reader sees that both halves were considered.
func renderFindingsSection(b *strings.Builder, label string, fs []report.Finding, color, reset string) {
	if len(fs) == 0 {
		fmt.Fprintf(b, "%s%s findings: (none)%s\n\n", color, label, reset)
		return
	}
	fmt.Fprintf(b, "%s%s findings (%d):%s\n", color, label, len(fs), reset)
	for _, f := range fs {
		fmt.Fprintf(b, "  [%s] %s -- %s\n", f.Severity, f.Cluster, f.Title)
	}
	fmt.Fprintln(b)
}

// RenderMarkdown returns a Markdown rendering of the diff suitable for
// pasting into a PR description or ticket.
func RenderMarkdown(d ScanDiff) string {
	var b strings.Builder
	delta := d.ScoreAfter - d.ScoreBefore
	deltaEmoji := "➡️"
	switch {
	case delta < 0:
		deltaEmoji = "⬇️"
	case delta > 0:
		deltaEmoji = "⬆️"
	}
	fmt.Fprintf(&b, "## Fleetsweeper scan diff\n\n")
	fmt.Fprintf(&b, "| Metric | Before | After | Delta |\n")
	fmt.Fprintf(&b, "| ------ | ------ | ----- | ----- |\n")
	fmt.Fprintf(&b, "| Fleet Score | %d (%s) | %d (%s) | %s %+d |\n",
		d.ScoreBefore, d.GradeBefore, d.ScoreAfter, d.GradeAfter, deltaEmoji, delta)
	fmt.Fprintf(&b, "| Critical findings | %d | %d | %+d |\n",
		d.CriticalBefore, d.CriticalAfter, d.CriticalAfter-d.CriticalBefore)
	fmt.Fprintf(&b, "| Warning findings | %d | %d | %+d |\n\n",
		d.WarningBefore, d.WarningAfter, d.WarningAfter-d.WarningBefore)

	if len(d.New) > 0 {
		fmt.Fprintf(&b, "### New findings (%d)\n\n", len(d.New))
		for _, f := range d.New {
			fmt.Fprintf(&b, "- **[%s]** `%s` -- %s\n", f.Severity, f.Cluster, f.Title)
		}
		fmt.Fprintln(&b)
	}
	if len(d.Resolved) > 0 {
		fmt.Fprintf(&b, "### Resolved findings (%d)\n\n", len(d.Resolved))
		for _, f := range d.Resolved {
			fmt.Fprintf(&b, "- **[%s]** `%s` -- %s\n", f.Severity, f.Cluster, f.Title)
		}
		fmt.Fprintln(&b)
	}
	if len(d.ClusterStatusChanges) > 0 {
		fmt.Fprintf(&b, "### Cluster status changes (%d)\n\n", len(d.ClusterStatusChanges))
		for _, c := range d.ClusterStatusChanges {
			fmt.Fprintf(&b, "- `%s`: %s -> %s\n", c.Cluster, c.Before, c.After)
		}
		fmt.Fprintln(&b)
	}
	if len(d.AddedClusters) > 0 || len(d.RemovedClusters) > 0 {
		fmt.Fprintln(&b, "### Fleet membership")
		if len(d.AddedClusters) > 0 {
			fmt.Fprintf(&b, "Added: %s\n\n", strings.Join(d.AddedClusters, ", "))
		}
		if len(d.RemovedClusters) > 0 {
			fmt.Fprintf(&b, "Removed: %s\n\n", strings.Join(d.RemovedClusters, ", "))
		}
	}
	return b.String()
}

// wrap returns an ANSI escape sequence for color code, or empty when color is off.
func wrap(code string, color bool) string {
	if !color {
		return ""
	}
	return "\033[" + code + "m"
}
