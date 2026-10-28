package compare

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestDiff_NewAndResolved(t *testing.T) {
	t.Parallel()
	a := &report.Report{
		FleetScore: report.FleetScore{Score: 80, Grade: "B"},
		Summary:    report.Summary{CriticalCount: 1, WarningCount: 2},
		Findings: []report.Finding{
			{Cluster: "c1", Scanner: "node-health", Title: "persisted", Severity: report.SeverityCritical},
			{Cluster: "c1", Scanner: "rbac", Title: "resolved", Severity: report.SeverityWarning},
		},
		ClusterHealths: []report.ClusterHealth{
			{Name: "c1", Status: "critical"},
		},
	}
	b := &report.Report{
		FleetScore: report.FleetScore{Score: 73, Grade: "C"},
		Summary:    report.Summary{CriticalCount: 2, WarningCount: 1},
		Findings: []report.Finding{
			{Cluster: "c1", Scanner: "node-health", Title: "persisted", Severity: report.SeverityCritical},
			{Cluster: "c1", Scanner: "certs", Title: "new", Severity: report.SeverityCritical},
		},
		ClusterHealths: []report.ClusterHealth{
			{Name: "c1", Status: "critical"},
			{Name: "c2", Status: "healthy"},
		},
	}
	d := Diff(a, b)
	if d.ScoreBefore != 80 || d.ScoreAfter != 73 {
		t.Errorf("scores: %d -> %d", d.ScoreBefore, d.ScoreAfter)
	}
	if len(d.New) != 1 || d.New[0].Title != "new" {
		t.Errorf("expected one new finding 'new'; got %+v", d.New)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].Title != "resolved" {
		t.Errorf("expected one resolved finding 'resolved'; got %+v", d.Resolved)
	}
	if len(d.Persisted) != 1 || d.Persisted[0].Title != "persisted" {
		t.Errorf("expected one persisted finding 'persisted'; got %+v", d.Persisted)
	}
	if len(d.AddedClusters) != 1 || d.AddedClusters[0] != "c2" {
		t.Errorf("expected c2 added; got %v", d.AddedClusters)
	}
}

func TestDiff_NilSafe(t *testing.T) {
	t.Parallel()
	d := Diff(nil, nil)
	if d.ScoreBefore != 0 || d.ScoreAfter != 0 {
		t.Errorf("nil/nil should be zero; got %+v", d)
	}
}

func TestDiff_NilA(t *testing.T) {
	t.Parallel()
	b := &report.Report{
		Findings: []report.Finding{{Cluster: "c1", Scanner: "s", Title: "t", Severity: "critical"}},
	}
	d := Diff(nil, b)
	if len(d.New) != 1 {
		t.Errorf("expected 1 new finding for first-scan diff; got %d", len(d.New))
	}
}

func TestDiff_ClusterStatusMoves(t *testing.T) {
	t.Parallel()
	a := &report.Report{ClusterHealths: []report.ClusterHealth{{Name: "c1", Status: "healthy"}}}
	b := &report.Report{ClusterHealths: []report.ClusterHealth{{Name: "c1", Status: "degraded"}}}
	d := Diff(a, b)
	if len(d.ClusterStatusChanges) != 1 {
		t.Fatalf("expected one cluster change; got %+v", d.ClusterStatusChanges)
	}
	c := d.ClusterStatusChanges[0]
	if c.Cluster != "c1" || c.Before != "healthy" || c.After != "degraded" {
		t.Errorf("unexpected change: %+v", c)
	}
}

func TestRenderText_IncludesAllSections(t *testing.T) {
	t.Parallel()
	d := ScanDiff{
		ScoreBefore: 80, ScoreAfter: 73, GradeBefore: "B", GradeAfter: "C",
		CriticalBefore: 1, CriticalAfter: 2,
		WarningBefore: 3, WarningAfter: 2,
		New:                  []report.Finding{{Cluster: "c1", Severity: "critical", Title: "new"}},
		Resolved:             []report.Finding{{Cluster: "c1", Severity: "warning", Title: "fixed"}},
		ClusterStatusChanges: []ClusterStatusChange{{Cluster: "c1", Before: "healthy", After: "degraded"}},
		AddedClusters:        []string{"c2"},
	}
	out := RenderText(d, false)
	for _, want := range []string{
		"Fleet Score:", "Critical:", "Warning:",
		"NEW findings (1)", "RESOLVED findings (1)",
		"Cluster status changes:", "Added clusters",
		"c1", "c2", "new", "fixed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderMarkdown_IncludesTables(t *testing.T) {
	t.Parallel()
	d := ScanDiff{
		ScoreBefore: 80, ScoreAfter: 73,
		GradeBefore: "B", GradeAfter: "C",
		New: []report.Finding{{Cluster: "c1", Severity: "critical", Title: "new"}},
	}
	out := RenderMarkdown(d)
	for _, want := range []string{
		"## Fleetsweeper scan diff",
		"| Metric | Before | After | Delta |",
		"### New findings (1)",
		"`c1`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderText_ColorWrappers(t *testing.T) {
	t.Parallel()
	d := ScanDiff{ScoreBefore: 80, ScoreAfter: 73}
	plain := RenderText(d, false)
	colored := RenderText(d, true)
	if strings.Contains(plain, "\033[") {
		t.Errorf("plain output should not contain ANSI codes")
	}
	if !strings.Contains(colored, "\033[") {
		t.Errorf("colored output should contain ANSI codes")
	}
}

// setFinding returns a CRD consensus finding for cluster lacking missing.
func setFinding(cluster string, missing ...string) report.Finding {
	return report.Finding{
		Rule: "crds/missing-consensus", Cluster: cluster, Scanner: "crds", Severity: report.SeverityWarning,
		Affected: []string{"crd_names"},
		Norm:     &report.NormBasis{Kind: report.NormKindSet, Missing: missing},
	}
}

// TestDiff_SetDrift verifies a persisted set finding reports the members it newly lacks and
// the ones it got back, and that unchanged or non-set persisted findings report nothing.
func TestDiff_SetDrift(t *testing.T) {
	t.Parallel()
	numeric := report.Finding{
		Rule: "security/outlier-enforced-count", Cluster: "c3", Scanner: "security",
		Norm: &report.NormBasis{Kind: report.NormKindNumeric, Median: 4},
	}
	a := &report.Report{Findings: []report.Finding{
		setFinding("c1", "a.example.com"),
		setFinding("c2", "a.example.com"),
		numeric,
	}}
	b := &report.Report{Findings: []report.Finding{
		setFinding("c1", "b.example.com", "c.example.com"),
		setFinding("c2", "a.example.com"),
		numeric,
	}}
	d := Diff(a, b)
	want := []SetDrift{{
		Cluster: "c1", Scanner: "crds", Field: "crd_names",
		NewlyMissing: []string{"b.example.com", "c.example.com"}, Restored: []string{"a.example.com"},
	}}
	if diff := cmp.Diff(want, d.SetDrift); diff != "" {
		t.Errorf("set drift mismatch (-want +got):\n%s", diff)
	}
	text := RenderText(d, false)
	if !strings.Contains(text, "c1 crds/crd_names: now missing b.example.com, c.example.com; restored a.example.com") {
		t.Errorf("text rendering lacks the set drift line:\n%s", text)
	}
	if md := RenderMarkdown(d); !strings.Contains(md, "### Set drift (1)") {
		t.Errorf("markdown rendering lacks the set drift section:\n%s", md)
	}
}

// enforcedReport builds a 10-cluster report on security/enforced_count with
// c04 at the given value.
func enforcedReport(c04 float64) *report.Report {
	base := []float64{20, 22, 23, 24, 24, 25, 26, 26, 28, 30}
	clusters := make([]string, 0, len(base))
	results := map[string]map[string]scanner.Result{}
	for i, v := range base {
		c := fmt.Sprintf("c%02d", i)
		if c == "c04" {
			v = c04
		}
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{"security": {Scanner: "security", Data: map[string]any{"enforced_count": v}}}
	}
	return report.Build(clusters, results)
}

// TestDiff_Drift verifies the diff carries the drift ledger from A to B and
// both renderings list the drifted cluster above the findings.
func TestDiff_Drift(t *testing.T) {
	t.Parallel()
	d := Diff(enforcedReport(24), enforcedReport(80))
	if len(d.Drift.Clusters) == 0 || d.Drift.Clusters[0].Cluster != "c04" {
		t.Fatalf("want c04 first in the drift ledger, got %+v", d.Drift.Clusters)
	}
	text := RenderText(d, false)
	line := "c04 deviation"
	if !strings.Contains(text, "Drifted clusters (") || !strings.Contains(text, line) ||
		!strings.Contains(text, "now flagged on security/enforced_count") {
		t.Errorf("text rendering lacks the drift block:\n%s", text)
	}
	if strings.Index(text, "Drifted clusters") > strings.Index(text, "NEW findings") {
		t.Errorf("drift block is not above the findings:\n%s", text)
	}
	if md := RenderMarkdown(d); !strings.Contains(md, "### Drifted clusters (") || !strings.Contains(md, line) {
		t.Errorf("markdown rendering lacks the drift block:\n%s", md)
	}
	if steady := Diff(enforcedReport(24), enforcedReport(24)); len(steady.Drift.Clusters) != 0 {
		t.Errorf("identical reports drifted: %+v", steady.Drift.Clusters)
	}
}

// TestDriftLinesLimit verifies the rendering caps the rows and counts the rest.
func TestDriftLinesLimit(t *testing.T) {
	t.Parallel()
	l := report.Ledger{}
	for i := range 4 {
		l.Clusters = append(l.Clusters, report.ClusterDrift{Cluster: fmt.Sprintf("c%d", i), MassAfter: 1, MassDelta: 1})
	}
	got := DriftLines(l, 2)
	want := []string{"c0 deviation 0.0 -> 1.0 (+1.0)", "c1 deviation 0.0 -> 1.0 (+1.0)", "... and 2 more"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("lines mismatch (-want +got):\n%s", diff)
	}
}

// TestFindingOrder verifies severity-descending order with a full tie-break.
func TestFindingOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In        []report.Finding
		WantOrder []string
	}{{ // Test 0: Unknown severity sorts after info.
		In: []report.Finding{
			{Title: "d", Severity: "debug", Cluster: "a"},
			{Title: "i", Severity: "info", Cluster: "a"},
			{Title: "w", Severity: "warning", Cluster: "a"},
			{Title: "c", Severity: "critical", Cluster: "a"},
		},
		WantOrder: []string{"c", "w", "i", "d"},
	}, { // Test 1: Ties break by cluster, title, then rule.
		In: []report.Finding{
			{Title: "t", Severity: "info", Cluster: "b", Rule: "r"},
			{Title: "u", Severity: "info", Cluster: "a", Rule: "r"},
			{Title: "t", Severity: "info", Cluster: "a", Rule: "z"},
			{Title: "t", Severity: "info", Cluster: "a", Rule: "y"},
		},
		WantOrder: []string{"t/a/y", "t/a/z", "u/a/r", "t/b/r"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			in := slices.Clone(test.In)
			slices.SortStableFunc(in, FindingOrder)
			var got []string
			for _, f := range in {
				if test.WantOrder[0] == "c" {
					got = append(got, f.Title)
					continue
				}
				got = append(got, f.Title+"/"+f.Cluster+"/"+f.Rule)
			}
			if diff := cmp.Diff(test.WantOrder, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
