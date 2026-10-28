package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// buildReportForDiffTest produces a small Report fixture with the
// fields ComputeWhatChanged actually consults.
func buildReportForDiffTest(score int, findings []report.Finding, healths []report.ClusterHealth) *report.Report {
	return &report.Report{
		Clusters:       []string{"a", "b"},
		FleetScore:     report.FleetScore{Score: score},
		Findings:       findings,
		ClusterHealths: healths,
	}
}

// TestComputeWhatChanged_DetectsNewAndCleared verifies findings present
// only in B count as new, present only in A count as cleared, and ones
// in both are excluded.
func TestComputeWhatChanged_DetectsNewAndCleared(t *testing.T) {
	t.Parallel()
	common := report.Finding{Title: "common", Severity: "warning", Cluster: "a", Scanner: "x", Rule: "x/common"}
	gone := report.Finding{Title: "gone", Severity: "critical", Cluster: "a", Scanner: "x", Rule: "x/gone"}
	added := report.Finding{Title: "new", Severity: "critical", Cluster: "b", Scanner: "y", Rule: "y/new"}

	a := buildReportForDiffTest(90,
		[]report.Finding{common, gone},
		[]report.ClusterHealth{{Name: "a", Status: "healthy"}, {Name: "b", Status: "healthy"}},
	)
	b := buildReportForDiffTest(80,
		[]report.Finding{common, added},
		[]report.ClusterHealth{{Name: "a", Status: "healthy"}, {Name: "b", Status: "degraded"}},
	)
	d := computeWhatChanged(a, b, "scan-a", "scan-b", "")

	if d.FleetScoreDelta != -10 {
		t.Errorf("delta: want -10, got %d", d.FleetScoreDelta)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Title != "new" {
		t.Errorf("new findings: %+v", d.NewFindings)
	}
	if len(d.ClearedFindings) != 1 || d.ClearedFindings[0].Title != "gone" {
		t.Errorf("cleared findings: %+v", d.ClearedFindings)
	}
	if len(d.ClusterScoreChanges) == 0 {
		t.Error("expected per-cluster score change from healthy -> degraded")
	}
}

// TestComputeWhatChanged_SeverityFilter restricts findings included in
// the diff to >= the requested severity.
func TestComputeWhatChanged_SeverityFilter(t *testing.T) {
	t.Parallel()
	a := buildReportForDiffTest(100, nil, nil)
	b := buildReportForDiffTest(95, []report.Finding{
		{Title: "info-thing", Severity: "info", Cluster: "a", Scanner: "x", Rule: "x/info"},
		{Title: "warn-thing", Severity: "warning", Cluster: "a", Scanner: "x", Rule: "x/warn"},
		{Title: "crit-thing", Severity: "critical", Cluster: "a", Scanner: "x", Rule: "x/crit"},
	}, nil)

	d := computeWhatChanged(a, b, "a", "b", "warning")
	titles := map[string]bool{}
	for _, f := range d.NewFindings {
		titles[f.Title] = true
	}
	if titles["info-thing"] {
		t.Error("info finding should be filtered out at severity=warning")
	}
	if !titles["warn-thing"] || !titles["crit-thing"] {
		t.Errorf("warning+ findings missing: %v", titles)
	}
}

// TestComputeWhatChanged_TitleCountChange verifies a finding whose title count
// changes between scans is neither new nor cleared, since findings match on
// cluster, scanner, and rule.
func TestComputeWhatChanged_TitleCountChange(t *testing.T) {
	t.Parallel()
	a := buildReportForDiffTest(90, []report.Finding{{
		Title: "a has 3 privileged containers", Severity: "critical", Cluster: "a",
		Scanner: "workload-security", Rule: "workload-security/privileged",
	}}, nil)
	b := buildReportForDiffTest(90, []report.Finding{{
		Title: "a has 5 privileged containers", Severity: "critical", Cluster: "a",
		Scanner: "workload-security", Rule: "workload-security/privileged",
	}}, nil)
	d := computeWhatChanged(a, b, "a", "b", "")
	if len(d.NewFindings) != 0 || len(d.ClearedFindings) != 0 {
		t.Errorf("want no new or cleared findings, got new %v cleared %v", d.NewFindings, d.ClearedFindings)
	}
}

// TestComputeWhatChanged_NoChangeRendersEmptyBlocks verifies a diff
// against an identical report yields no new/cleared/cluster entries.
func TestComputeWhatChanged_NoChangeRendersEmptyBlocks(t *testing.T) {
	t.Parallel()
	rpt := buildReportForDiffTest(85,
		[]report.Finding{{Title: "x", Severity: "warning", Cluster: "a", Scanner: "y"}},
		[]report.ClusterHealth{{Name: "a", Status: "healthy"}},
	)
	d := computeWhatChanged(rpt, rpt, "id", "id", "")
	if len(d.NewFindings) != 0 || len(d.ClearedFindings) != 0 ||
		len(d.ClusterScoreChanges) != 0 || d.FleetScoreDelta != 0 {
		t.Errorf("expected empty diff, got %+v", d)
	}
}

// TestWriteWhatChanged_HumanIncludesFleetDelta and per-cluster section
// covers the rendering path.
func TestWriteWhatChanged_HumanIncludesFleetDelta(t *testing.T) {
	t.Parallel()
	d := whatChangedDiff{
		ScanA: "a", ScanB: "b",
		FleetScoreA: 90, FleetScoreB: 80, FleetScoreDelta: -10,
		NewFindings:     []report.Finding{{Title: "T", Cluster: "c1", Severity: "critical"}},
		ClearedFindings: nil,
		ClusterScoreChanges: []clusterScoreChange{
			{Cluster: "c1", ScoreA: 90, ScoreB: 60, Delta: -30, GradeA: "A", GradeB: "D"},
		},
	}
	buf := &bytes.Buffer{}
	if err := writeWhatChanged(buf, d, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Fleet score: 90 -> 80 (-10)") {
		t.Errorf("missing fleet delta line: %s", out)
	}
	if !strings.Contains(out, "[CRITICAL] c1 -- T") {
		t.Errorf("missing new-finding line: %s", out)
	}
	if !strings.Contains(out, "c1") || !strings.Contains(out, "-30") {
		t.Errorf("missing cluster score change: %s", out)
	}
}

// TestWriteWhatChanged_JSON verifies the structured serialization.
func TestWriteWhatChanged_JSON(t *testing.T) {
	t.Parallel()
	d := whatChangedDiff{
		ScanA: "a", ScanB: "b",
		FleetScoreA: 50, FleetScoreB: 55, FleetScoreDelta: 5,
	}
	buf := &bytes.Buffer{}
	if err := writeWhatChanged(buf, d, true); err != nil {
		t.Fatalf("render: %v", err)
	}
	var got whatChangedDiff
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ScanA != "a" || got.FleetScoreDelta != 5 {
		t.Errorf("decoded: %+v", got)
	}
}

// TestSortFindings verifies severity-descending order with a full tie-break.
func TestSortFindings(t *testing.T) {
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
			sortFindings(in)
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
