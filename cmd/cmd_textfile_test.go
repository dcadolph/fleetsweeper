package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestWriteProm_AllSectionsRendered verifies the Prometheus exposition
// includes the fleet score, findings, cluster count, per-cluster
// scores, and outliers when present.
func TestWriteProm_AllSectionsRendered(t *testing.T) {
	t.Parallel()
	rpt := &report.Report{
		Clusters: []string{"a", "b"},
		Summary: report.Summary{
			ClusterCount:  2,
			CriticalCount: 3,
			WarningCount:  5,
		},
		FleetScore: report.FleetScore{Score: 82},
		ClusterHealths: []report.ClusterHealth{
			{Name: "a", Status: "healthy"},
			{Name: "b", Status: "degraded"},
		},
		Outliers: []report.OutlierResult{
			{Cluster: "b", Field: "version", Scanner: "version", Severity: "warning"},
		},
	}
	buf := &bytes.Buffer{}
	if err := writeProm(buf, rpt, "scan-123", time.Unix(1700000000, 0).UTC()); err != nil {
		t.Fatalf("writeProm: %v", err)
	}
	out := buf.String()
	wants := []string{
		`fleetsweeper_fleet_score{scan_id="scan-123"} 82`,
		`fleetsweeper_fleet_score_timestamp_seconds 1700000000`,
		`fleetsweeper_findings_total{severity="critical"} 3`,
		`fleetsweeper_findings_total{severity="warning"} 5`,
		`fleetsweeper_clusters_total 2`,
		`fleetsweeper_cluster_score{cluster="a"`,
		`fleetsweeper_cluster_score{cluster="b"`,
		`fleetsweeper_cluster_outlier{cluster="b"} 1`,
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// TestWriteProm_OmitsOutliersSectionWhenNone verifies the outlier block
// is suppressed (no HELP, no TYPE) when the report has no outliers.
func TestWriteProm_OmitsOutliersSectionWhenNone(t *testing.T) {
	t.Parallel()
	rpt := &report.Report{
		Clusters: []string{"a"},
		Summary:  report.Summary{ClusterCount: 1},
	}
	buf := &bytes.Buffer{}
	if err := writeProm(buf, rpt, "scan", time.Now()); err != nil {
		t.Fatalf("writeProm: %v", err)
	}
	if strings.Contains(buf.String(), "fleetsweeper_cluster_outlier") {
		t.Error("outlier section should be omitted when none present")
	}
}

// TestEscapeLabel verifies the label escaper handles the three
// Prometheus-special characters and leaves clean input alone.
func TestEscapeLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In   string
		Want string
	}{
		{"plain", "plain"},
		{`with"quote`, `with\"quote`},
		{`with\backslash`, `with\\backslash`},
		{"with\nnewline", `with\nnewline`},
	}
	for i, tc := range tests {
		if got := escapeLabel(tc.In); got != tc.Want {
			t.Errorf("test %d: got %q, want %q", i, got, tc.Want)
		}
	}
}
