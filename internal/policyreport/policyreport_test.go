package policyreport

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

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
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := ruleFromTitle(c.In); got != c.Want {
				t.Errorf("rule(%q): want %q, got %q", c.In, c.Want, got)
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

func TestSanitizeName(t *testing.T) {
	t.Parallel()
	if got := sanitizeName("Prod_US-east-1!"); got != "prod-us-east-1" {
		t.Errorf("sanitize: got %q", got)
	}
	if got := sanitizeName(""); got != "unnamed" {
		t.Errorf("sanitize empty: got %q", got)
	}
}
