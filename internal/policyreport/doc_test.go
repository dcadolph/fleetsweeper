package policyreport

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

const docPath = "../../docs/integrations/policyreport.md"

// docExampleYAML returns the first yaml block after the "## Resource shape" heading.
func docExampleYAML(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read doc: %v", err)
	}
	_, after, found := strings.Cut(string(data), "## Resource shape")
	if !found {
		t.Fatal("doc has no Resource shape heading")
	}
	_, block, found := strings.Cut(after, "```yaml\n")
	if !found {
		t.Fatal("doc has no yaml block after Resource shape")
	}
	body, _, found := strings.Cut(block, "```")
	if !found {
		t.Fatal("doc yaml block is not closed")
	}
	return []byte(body)
}

// TestPolicyReportDocExample verifies the documented resource shape matches ReportsFor output.
func TestPolicyReportDocExample(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In report.Report
	}{{ // Test 0: One image-audit finding on prod-east.
		In: report.Report{
			Timestamp: time.Date(2025, 5, 17, 13, 20, 0, 0, time.UTC).Format(time.RFC3339),
			Clusters:  []string{"prod-east"},
			Findings: []report.Finding{{
				Severity: report.SeverityWarning,
				Cluster:  "prod-east",
				Scanner:  "image-audit",
				Rule:     "image-audit/digest-pinning",
				Title:    "Image not pinned by digest",
				Remediation: &report.Remediation{
					Command: "kubectl set image deploy/foo container=image@sha256:abc123",
				},
			}},
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var want PolicyReport
			if err := yaml.UnmarshalStrict(docExampleYAML(t), &want); err != nil {
				t.Fatalf("unmarshal doc example: %v", err)
			}
			got := ReportsFor(&test.In, "scan-1", "fleetsweeper")
			if len(got) != 1 {
				t.Fatalf("want 1 report, got %d", len(got))
			}
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.IgnoreFields(Result{}, "Timestamp", "Resources"),
				cmpopts.IgnoreFields(PolicyReport{}, "Summary"),
			}
			if diff := cmp.Diff(want, got[0], opts...); diff != "" {
				t.Errorf("doc example mismatch (-doc +emitted):\n%s", diff)
			}
		})
	}
}
