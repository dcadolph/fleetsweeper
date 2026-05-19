package compare

import (
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
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
		WarningBefore:  3, WarningAfter:  2,
		New:      []report.Finding{{Cluster: "c1", Severity: "critical", Title: "new"}},
		Resolved: []report.Finding{{Cluster: "c1", Severity: "warning", Title: "fixed"}},
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
