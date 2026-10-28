package fleetdrift

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

func TestReportsFor_Basic(t *testing.T) {
	t.Parallel()
	r := &report.Report{
		Timestamp:  time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Clusters:   []string{"prod-us-east-1", "Prod_EU-west-1"},
		FleetScore: report.FleetScore{Score: 73, Grade: "C"},
		Findings: []report.Finding{
			{Severity: report.SeverityCritical, Cluster: "prod-us-east-1", Scanner: "node-health", Title: "node down"},
			{Severity: report.SeverityWarning, Cluster: "fleet", Scanner: "version", Title: "skew"},
		},
	}
	reports := ReportsFor(r, "scan-abc", "fleetsweeper")
	if len(reports) != 2 {
		t.Fatalf("want 2 reports, got %d", len(reports))
	}

	// Names must be DNS-1123-safe (lowercase, no underscores).
	for _, rep := range reports {
		if rep.Metadata.Name == "" {
			t.Errorf("empty name on report %+v", rep.Metadata)
		}
		if rep.Metadata.Name != util.SanitizeName(rep.Spec.Cluster) {
			t.Errorf("name sanitization mismatch for %q", rep.Spec.Cluster)
		}
		if rep.Metadata.Namespace != "fleetsweeper" {
			t.Errorf("namespace not propagated: %q", rep.Metadata.Namespace)
		}
		if rep.Spec.FleetScore.Score != 73 || rep.Spec.FleetScore.Grade != "C" {
			t.Errorf("fleet score not propagated: %+v", rep.Spec.FleetScore)
		}
	}

	// Fleet-scoped findings appear on every cluster's report.
	for _, rep := range reports {
		var sawFleetFinding bool
		for _, f := range rep.Status.Findings {
			if f.Title == "skew" {
				sawFleetFinding = true
			}
		}
		if !sawFleetFinding {
			t.Errorf("fleet finding missing from %s", rep.Spec.Cluster)
		}
	}

	// The prod-us cluster sees its own critical finding.
	var prodUS *Report
	for i := range reports {
		if reports[i].Spec.Cluster == "prod-us-east-1" {
			prodUS = &reports[i]
		}
	}
	if prodUS == nil {
		t.Fatalf("prod-us-east-1 report missing")
	}
	if prodUS.Status.Summary.Critical != 1 {
		t.Errorf("prod-us critical count: want 1, got %d", prodUS.Status.Summary.Critical)
	}
}

func TestWrite_ReadBack(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rep := Report{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata: Metadata{
			Name:      "prod",
			Namespace: "fleetsweeper",
			Labels:    map[string]string{"fleetsweeper.io/cluster": "prod"},
		},
		Spec: Spec{Cluster: "prod", ScanID: "abc", ScanTime: time.Now().UTC(),
			FleetScore: FleetScoreSpec{Score: 80, Grade: "B"}},
		Status: Status{
			ObservedAt: time.Now().UTC(),
			Summary:    Summary{Critical: 1},
			Findings: []FindingSpec{
				{Severity: "critical", Scanner: "node-health", Title: "x"},
			},
		},
	}
	if err := Write([]Report{rep}, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	path := filepath.Join(dir, "prod.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got Report
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Spec.Cluster != "prod" {
		t.Errorf("round-trip cluster mismatch: %s", got.Spec.Cluster)
	}
	if got.APIVersion != APIVersion {
		t.Errorf("apiVersion mismatch: %s", got.APIVersion)
	}
	if got.Status.Summary.Critical != 1 {
		t.Errorf("summary critical mismatch: %d", got.Status.Summary.Critical)
	}
}

func TestReportsFor_NilReport(t *testing.T) {
	t.Parallel()
	if got := ReportsFor(nil, "id", ""); got != nil {
		t.Errorf("expected nil for nil report, got %+v", got)
	}
}

func TestWrite_EmptyDir(t *testing.T) {
	t.Parallel()
	if err := Write(nil, ""); err == nil {
		t.Errorf("expected error for empty dir, got nil")
	}
}
