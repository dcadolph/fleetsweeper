package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// summaryFinding returns a finding with a remediation, so it ranks as a recommendation.
func summaryFinding(cluster, rule, severity string) report.Finding {
	return report.Finding{
		Cluster: cluster, Scanner: "workload-security", Rule: rule, Severity: severity,
		Remediation: &report.Remediation{Command: "kubectl get pods -A"},
	}
}

// TestWriteScanSummary verifies the terminal summary leads with coverage, then the score, then
// the three fixes with the most leverage, and that an ungraded score says so instead of a grade.
func TestWriteScanSummary(t *testing.T) {
	t.Parallel()
	findings := []report.Finding{
		summaryFinding("a", "workload-security/privileged", "critical"),
		summaryFinding("b", "workload-security/privileged", "critical"),
		summaryFinding("a", "workload-security/host-network", "warning"),
		summaryFinding("c", "workload-security/host-pid", "warning"),
		summaryFinding("c", "workload-security/run-as-root", "info"),
	}
	tests := []struct {
		Report     *report.Report
		WantPrefix []string
	}{{ // Test 0: Graded scan prints coverage, score, then three fixes by leverage.
		Report: &report.Report{
			Clusters: []string{"a", "b", "c"},
			Findings: findings,
			FleetScore: report.FleetScore{
				Score: 72, Grade: "C", Graded: true, Headline: "Two clusters drifted.",
				Coverage: report.FleetCoverage{ExpectedRuns: 72, ObservedRuns: 70, BlindRuns: 2},
			},
		},
		WantPrefix: []string{
			"Coverage: 70 of 72 scanner runs observed across 3 clusters.",
			"Score: 72 (C). Two clusters drifted.",
			"Fix 1:",
			"Fix 2:",
			"Fix 3:",
		},
	}, { // Test 1: Ungraded scan names the blind clusters and gives no grade.
		Report: &report.Report{
			Clusters: []string{"a", "b"},
			FleetScore: report.FleetScore{
				Score: 100, Graded: false, Headline: "Not enough data.",
				Coverage: report.FleetCoverage{ExpectedRuns: 48, ObservedRuns: 0, BlindRuns: 48, BlindClusters: 2},
			},
		},
		WantPrefix: []string{
			"Coverage: 0 of 48 scanner runs observed across 2 clusters. 2 clusters had no complete run.",
			"Score: not graded. Not enough data.",
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			writeScanSummary(&buf, test.Report)
			lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			if len(lines) < len(test.WantPrefix) {
				t.Fatalf("got %d lines, want at least %d:\n%s", len(lines), len(test.WantPrefix), buf.String())
			}
			got := make([]string, len(test.WantPrefix))
			for i, want := range test.WantPrefix {
				got[i] = lines[i]
				if strings.HasPrefix(lines[i], want) {
					got[i] = want
				}
			}
			if diff := cmp.Diff(test.WantPrefix, got); diff != "" {
				t.Errorf("line order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestWriteScanSummaryFixOrder verifies the first fix is the one that reaches the most clusters
// at the highest severity, and that no more than three are printed.
func TestWriteScanSummaryFixOrder(t *testing.T) {
	t.Parallel()
	rpt := &report.Report{
		Clusters: []string{"a", "b", "c"},
		Findings: []report.Finding{
			summaryFinding("a", "workload-security/privileged", "critical"),
			summaryFinding("b", "workload-security/privileged", "critical"),
			summaryFinding("a", "workload-security/host-network", "warning"),
			summaryFinding("c", "workload-security/host-pid", "warning"),
			summaryFinding("c", "workload-security/run-as-root", "info"),
		},
		FleetScore: report.FleetScore{Score: 72, Grade: "C", Graded: true},
	}
	var buf bytes.Buffer
	writeScanSummary(&buf, rpt)
	out := buf.String()
	if n := strings.Count(out, "Fix "); n != 3 {
		t.Errorf("want 3 fixes, got %d:\n%s", n, out)
	}
	first := out[strings.Index(out, "Fix 1:"):]
	first = first[:strings.Index(first, "\n")]
	if !strings.Contains(first, report.RuleTitle("workload-security/privileged")) || !strings.Contains(first, "2 clusters") {
		t.Errorf("first fix should be privileged on 2 clusters, got %q", first)
	}
}
