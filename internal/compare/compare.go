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
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
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
	// SetDrift lists persisted set-membership findings whose missing members
	// changed, so a cluster that loses another CRD shows up even though its
	// finding persisted.
	SetDrift []SetDrift `json:"set_drift"`
	// Drift is the drift ledger from A to B: which clusters moved against
	// the fleet norm, by how much, and on which fields.
	Drift report.Ledger `json:"drift"`
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

// SetDrift is a change in the consensus members one cluster lacks for one set
// field between two reports.
type SetDrift struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// Scanner is the scanner that reported the set.
	Scanner string `json:"scanner"`
	// Field is the set field, e.g. crd_names.
	Field string `json:"field"`
	// NewlyMissing are consensus members missing in B that were not missing in A.
	NewlyMissing []string `json:"newly_missing"`
	// Restored are members missing in A that are no longer missing in B.
	Restored []string `json:"restored"`
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
	out.Drift = report.DriftLedger([]report.ScanReport{{Report: a}, {Report: b}})
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

// populateFindings categorizes every finding in A and B into New, Resolved,
// or Persisted. Identity is the fingerprint (cluster+scanner+rule) so a count
// change in a title does not flip a persisted finding into resolved+new.
func (d *ScanDiff) populateFindings(a, b *report.Report) {
	keyOf := report.FindingFingerprint

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
		if prev, ok := aIdx[k]; ok {
			d.Persisted = append(d.Persisted, f)
			if sd, changed := setDrift(prev, f); changed {
				d.SetDrift = append(d.SetDrift, sd)
			}
		} else {
			d.New = append(d.New, f)
		}
	}
	for k, f := range aIdx {
		if _, ok := bIdx[k]; !ok {
			d.Resolved = append(d.Resolved, f)
		}
	}
	slices.SortStableFunc(d.New, FindingOrder)
	slices.SortStableFunc(d.Resolved, FindingOrder)
	slices.SortStableFunc(d.Persisted, FindingOrder)
	sort.Slice(d.SetDrift, func(i, j int) bool {
		if d.SetDrift[i].Cluster != d.SetDrift[j].Cluster {
			return d.SetDrift[i].Cluster < d.SetDrift[j].Cluster
		}
		if d.SetDrift[i].Scanner != d.SetDrift[j].Scanner {
			return d.SetDrift[i].Scanner < d.SetDrift[j].Scanner
		}
		return d.SetDrift[i].Field < d.SetDrift[j].Field
	})
}

// setDrift compares the missing members of one set finding across two reports.
// It reports changed only when both carry a set norm and the missing lists differ.
func setDrift(a, b report.Finding) (SetDrift, bool) {
	if a.Norm == nil || b.Norm == nil || a.Norm.Kind != report.NormKindSet || b.Norm.Kind != report.NormKindSet {
		return SetDrift{}, false
	}
	before := make(map[string]struct{}, len(a.Norm.Missing))
	for _, m := range a.Norm.Missing {
		before[m] = struct{}{}
	}
	after := make(map[string]struct{}, len(b.Norm.Missing))
	for _, m := range b.Norm.Missing {
		after[m] = struct{}{}
	}
	sd := SetDrift{Cluster: b.Cluster, Scanner: b.Scanner}
	if len(b.Affected) > 0 {
		sd.Field = b.Affected[0]
	}
	for _, m := range b.Norm.Missing {
		if _, ok := before[m]; !ok {
			sd.NewlyMissing = append(sd.NewlyMissing, m)
		}
	}
	for _, m := range a.Norm.Missing {
		if _, ok := after[m]; !ok {
			sd.Restored = append(sd.Restored, m)
		}
	}
	sort.Strings(sd.NewlyMissing)
	sort.Strings(sd.Restored)
	return sd, len(sd.NewlyMissing) > 0 || len(sd.Restored) > 0
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

// FindingOrder orders findings by descending severity, then cluster, title, and rule. Unknown
// severities sort after info.
func FindingOrder(a, b report.Finding) int {
	return cmp.Or(
		cmp.Compare(util.SeverityRank(b.Severity), util.SeverityRank(a.Severity)),
		strings.Compare(a.Cluster, b.Cluster),
		strings.Compare(a.Title, b.Title),
		strings.Compare(a.Rule, b.Rule),
	)
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

	if len(d.Drift.Clusters) > 0 {
		fmt.Fprintf(&b, "%sDrifted clusters (%d):%s\n", yellow, len(d.Drift.Clusters), reset())
		for _, line := range DriftLines(d.Drift, maxDriftLines) {
			fmt.Fprintf(&b, "  %s\n", line)
		}
		fmt.Fprintln(&b)
	}
	renderFindingsSection(&b, "NEW", d.New, red, reset())
	renderFindingsSection(&b, "RESOLVED", d.Resolved, green, reset())

	if len(d.SetDrift) > 0 {
		fmt.Fprintf(&b, "%sSet drift (%d):%s\n", yellow, len(d.SetDrift), reset())
		for _, s := range d.SetDrift {
			fmt.Fprintf(&b, "  %s %s/%s:%s\n", s.Cluster, s.Scanner, s.Field, setDriftText(s))
		}
		fmt.Fprintln(&b)
	}
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

// renderFindingsSection writes a labeled list of findings to b. Empty
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

	if len(d.Drift.Clusters) > 0 {
		fmt.Fprintf(&b, "### Drifted clusters (%d)\n\n", len(d.Drift.Clusters))
		for _, line := range DriftLines(d.Drift, maxDriftLines) {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		fmt.Fprintln(&b)
	}
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
	if len(d.SetDrift) > 0 {
		fmt.Fprintf(&b, "### Set drift (%d)\n\n", len(d.SetDrift))
		for _, s := range d.SetDrift {
			fmt.Fprintf(&b, "- `%s` %s/%s:%s\n", s.Cluster, s.Scanner, s.Field, setDriftText(s))
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

// maxDriftLines is how many drifted clusters the text and Markdown renderings
// list before summarizing the rest.
const maxDriftLines = 10

// DriftLines renders up to limit ledger rows as one line each: the cluster,
// how its deviation mass moved, the field that moved most, and the outlier
// flags it gained or lost with the scan of each flip when known. A final line
// counts the rows left out.
func DriftLines(l report.Ledger, limit int) []string {
	var out []string
	for i, c := range l.Clusters {
		if i == limit {
			out = append(out, fmt.Sprintf("... and %d more", len(l.Clusters)-limit))
			break
		}
		parts := []string{fmt.Sprintf("%s deviation %.1f -> %.1f (%+.1f)", c.Cluster, c.MassBefore, c.MassAfter, c.MassDelta)}
		if len(c.Fields) > 0 {
			f := c.Fields[0]
			parts = append(parts, fmt.Sprintf("%s/%s %s -> %s (z %.1f -> %.1f)",
				f.Scanner, f.Field, orDash(f.Before), orDash(f.After), f.ZBefore, f.ZAfter))
		}
		for _, g := range c.Gained {
			parts = append(parts, "now flagged on "+flagText(g))
		}
		for _, g := range c.Lost {
			parts = append(parts, "no longer flagged on "+flagText(g))
		}
		out = append(out, strings.Join(parts, ", "))
	}
	return out
}

// flagText renders a flag change as scanner/field, with the scan it flipped in
// when known.
func flagText(f report.FlagChange) string {
	if f.Scan == "" {
		return f.Scanner + "/" + f.Field
	}
	return fmt.Sprintf("%s/%s since %s", f.Scanner, f.Field, f.Scan)
}

// orDash returns s, or "-" when s is empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// setDriftText renders the newly missing and restored members of s, e.g.
// " now missing a, b; restored c".
func setDriftText(s SetDrift) string {
	var parts []string
	if len(s.NewlyMissing) > 0 {
		parts = append(parts, "now missing "+strings.Join(s.NewlyMissing, ", "))
	}
	if len(s.Restored) > 0 {
		parts = append(parts, "restored "+strings.Join(s.Restored, ", "))
	}
	return " " + strings.Join(parts, "; ")
}

// wrap returns an ANSI escape sequence for color code, or empty when color is off.
func wrap(code string, color bool) string {
	if !color {
		return ""
	}
	return "\033[" + code + "m"
}
