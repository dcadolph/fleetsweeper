package policyreport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"sigs.k8s.io/yaml"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

func TestReportsFor_PerClusterAndFleetFindings(t *testing.T) {
	t.Parallel()
	r := &report.Report{
		Timestamp: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Clusters:  []string{"prod-east", "prod-west"},
		Findings: []report.Finding{
			{Severity: report.SeverityCritical, Cluster: "prod-east", Scanner: "node-health",
				Title: "node down", Description: "1 of 18 nodes not ready",
				Affected: []string{"ip-10-0-12-44.ec2.internal"}},
			{Severity: report.SeverityWarning, Cluster: "fleet", Scanner: "version",
				Title: "version skew"},
		},
	}
	out := ReportsFor(r, "scan-1", "fleetsweeper")
	if len(out) != 2 {
		t.Fatalf("want 2 reports, got %d", len(out))
	}
	for _, pr := range out {
		if pr.APIVersion != APIVersion {
			t.Errorf("apiVersion: want %s, got %s", APIVersion, pr.APIVersion)
		}
		if pr.Kind != Kind {
			t.Errorf("kind: want %s, got %s", Kind, pr.Kind)
		}
		if pr.Metadata.Namespace != "fleetsweeper" {
			t.Errorf("namespace: want fleetsweeper, got %s", pr.Metadata.Namespace)
		}
		// Every report should include the fleet-scoped finding.
		var sawFleet bool
		for _, res := range pr.Results {
			if res.Message == "version skew" || res.Policy == "version" {
				sawFleet = true
			}
		}
		if !sawFleet {
			t.Errorf("fleet finding missing from %s", pr.Metadata.Name)
		}
	}
	// Summary tallies on prod-east include 1 fail (critical) + 1 fail (warning).
	var east *PolicyReport
	for i := range out {
		if out[i].Metadata.Labels["fleetsweeper.io/cluster"] == "prod-east" {
			east = &out[i]
		}
	}
	if east == nil {
		t.Fatalf("prod-east report missing")
	}
	if east.Summary.Fail != 2 {
		t.Errorf("prod-east fail count: want 2, got %d", east.Summary.Fail)
	}
}

func TestSeverityAndResultMap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		Sev          string
		WantSeverity string
		WantResult   string
	}{
		{report.SeverityCritical, "critical", "fail"},
		{report.SeverityWarning, "medium", "fail"},
		{report.SeverityInfo, "info", "warn"},
		{"unknown", "info", "warn"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := severityMap(c.Sev); got != c.WantSeverity {
				t.Errorf("severity(%q): want %q, got %q", c.Sev, c.WantSeverity, got)
			}
			if got := resultMap(c.Sev); got != c.WantResult {
				t.Errorf("result(%q): want %q, got %q", c.Sev, c.WantResult, got)
			}
		})
	}
}

func TestParseResourceRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		In   string
		Want ResourceRef
	}{
		{"Deployment payments/api", ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
		{"kube-system/coredns", ResourceRef{Namespace: "kube-system", Name: "coredns"}},
		{"node-1", ResourceRef{Name: "node-1"}},
		{"", ResourceRef{Name: "(unknown)"}},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			got := parseResourceRef(c.In)
			if got != c.Want {
				t.Errorf("parse(%q): want %+v, got %+v", c.In, c.Want, got)
			}
		})
	}
}

func TestRuleFromTitle(t *testing.T) {
	t.Parallel()
	cases := []struct{ In, Want string }{
		{"prod-east has 2 node(s) under memory pressure", "prod-east"},
		{"NodeReady: false", "NodeReady"},
		{"shorttitle", "shorttitle"},
		{strings.Repeat("é", 70), strings.Repeat("é", 60)},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			got := ruleFromTitle(c.In)
			if got != c.Want {
				t.Errorf("rule(%q): want %q, got %q", c.In, c.Want, got)
			}
			if !utf8.ValidString(got) {
				t.Errorf("rule(%q): invalid UTF-8 %q", c.In, got)
			}
		})
	}
}

func TestWrite_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pr := PolicyReport{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata: Metadata{
			Name:      "fleetsweeper-prod",
			Namespace: "fleetsweeper",
			Labels:    map[string]string{"fleetsweeper.io/cluster": "prod"},
		},
		Summary: Summary{Fail: 1, Warn: 2},
		Results: []Result{
			{Source: Source, Policy: "node-health", Severity: "critical",
				Result: "fail", Message: "node down"},
		},
	}
	if err := Write([]PolicyReport{pr}, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "fleetsweeper-prod.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got PolicyReport
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.APIVersion != APIVersion {
		t.Errorf("apiVersion mismatch: %s", got.APIVersion)
	}
	if got.Summary.Fail != 1 {
		t.Errorf("summary fail: want 1, got %d", got.Summary.Fail)
	}
}

func TestReportsFor_NilSafe(t *testing.T) {
	t.Parallel()
	if got := ReportsFor(nil, "id", "ns"); got != nil {
		t.Errorf("want nil for nil report, got %+v", got)
	}
}

// TestReportsForNameLength verifies the prefixed metadata.name never exceeds the Kubernetes name
// limit, however long the cluster name is.
func TestReportsForNameLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Cluster    string
		WantResult string
	}{{ // Test 0: A short name keeps the prefix.
		Cluster: "Prod_East", WantResult: "fleetsweeper-prod-east",
	}, { // Test 1: A long name is cut to 253 characters including the 13-character prefix.
		Cluster: strings.Repeat("a", 300), WantResult: "fleetsweeper-" + strings.Repeat("a", 240),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := &report.Report{Clusters: []string{test.Cluster}}
			out := ReportsFor(r, "scan-1", "fleetsweeper")
			if len(out) != 1 {
				t.Fatalf("want 1 report, got %d", len(out))
			}
			if got := out[0].Metadata.Name; got != test.WantResult {
				t.Errorf("name = %q (%d chars), want %q", got, len(got), test.WantResult)
			}
		})
	}
}

// TestReportsForCategories verifies that results carry the report category of their scanner.
func TestReportsForCategories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner    string
		WantResult string
	}{
		{Scanner: "cluster-info", WantResult: "Health & Resources"},   // Test 0: Node drift.
		{Scanner: "vulnerabilities", WantResult: "Security & Access"}, // Test 1: Vulnerabilities.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := &report.Report{
				Clusters: []string{"c1"},
				Findings: []report.Finding{{
					Severity: report.SeverityWarning, Cluster: "c1", Scanner: test.Scanner, Title: "t",
				}},
			}
			out := ReportsFor(r, "scan-1", "fleetsweeper")
			if len(out) != 1 || len(out[0].Results) != 1 {
				t.Fatalf("want 1 report with 1 result, got %+v", out)
			}
			if diff := cmp.Diff(test.WantResult, out[0].Results[0].Category); diff != "" {
				t.Errorf("category mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToResultRule(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		In       report.Finding
		WantRule string
	}{{ // Test 0: Finding rule wins over a title with a count.
		In: report.Finding{Scanner: "image-audit", Rule: "image-audit/digest-pinning",
			Title: "12 images are not pinned by digest"},
		WantRule: "image-audit/digest-pinning",
	}, { // Test 1: Empty rule falls back to the title.
		In:       report.Finding{Scanner: "node-health", Title: "NodeReady: false"},
		WantRule: "NodeReady",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := toResult(test.In, ts).Rule; got != test.WantRule {
				t.Errorf("rule: want %q, got %q", test.WantRule, got)
			}
		})
	}
}

// TestCategoryForScannerMatchesReport verifies that every report category scanner maps to its
// category and an unknown scanner maps to Other.
func TestCategoryForScannerMatchesReport(t *testing.T) {
	t.Parallel()
	for _, c := range report.Categories() {
		for _, s := range c.Scanners {
			if got := report.CategoryOf(s); got != c.Name {
				t.Errorf("scanner %q: want %q, got %q", s, c.Name, got)
			}
		}
	}
	if got := report.CategoryOf("unknown-scanner"); got != "Other" {
		t.Errorf("unknown scanner: want Other, got %q", got)
	}
}
