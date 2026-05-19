package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner/policyreportingest"
)

// TestEmitPolicyReportMetrics_AggregatesAcrossClusters verifies a
// report containing the policy-reports scanner output from two
// clusters produces a single per-(source, result) gauge with the
// summed counts.
func TestEmitPolicyReportMetrics_AggregatesAcrossClusters(t *testing.T) {
	t.Parallel()
	perCluster := map[string]any{
		"a": map[string]any{
			"available": true,
			"by_source": []any{
				map[string]any{"source": "kyverno", "pass": 100, "fail": 4, "warn": 1},
				map[string]any{"source": "gatekeeper", "pass": 10, "fail": 2},
			},
		},
		"b": map[string]any{
			"available": true,
			"by_source": []any{
				map[string]any{"source": "kyverno", "pass": 200, "fail": 6},
				map[string]any{"source": "trivy", "warn": 12},
			},
		},
	}
	rpt := &report.Report{
		Sections: map[string]*report.SectionReport{
			policyreportingest.Name: {PerCluster: perCluster},
		},
	}
	buf := &bytes.Buffer{}
	emitPolicyReportMetrics(buf, rpt)
	out := buf.String()
	wants := []string{
		`fleetsweeper_policy_results_total{source="kyverno",result="pass"} 300`,
		`fleetsweeper_policy_results_total{source="kyverno",result="fail"} 10`,
		`fleetsweeper_policy_results_total{source="kyverno",result="warn"} 1`,
		`fleetsweeper_policy_results_total{source="gatekeeper",result="fail"} 2`,
		`fleetsweeper_policy_results_total{source="trivy",result="warn"} 12`,
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// TestEmitPolicyReportMetrics_NoOpWhenUnavailable verifies a section
// with available=false produces no output.
func TestEmitPolicyReportMetrics_NoOpWhenUnavailable(t *testing.T) {
	t.Parallel()
	rpt := &report.Report{
		Sections: map[string]*report.SectionReport{
			policyreportingest.Name: {PerCluster: map[string]any{
				"a": map[string]any{"available": false},
			}},
		},
	}
	buf := &bytes.Buffer{}
	emitPolicyReportMetrics(buf, rpt)
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}

// TestEmitPolicyReportMetrics_NoOpWhenMissingSection verifies an empty
// Sections map produces no output (and doesn't panic).
func TestEmitPolicyReportMetrics_NoOpWhenMissingSection(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	emitPolicyReportMetrics(buf, &report.Report{})
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}
