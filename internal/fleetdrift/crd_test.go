package fleetdrift

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// loadCRD parses the FleetDriftReport CRD manifest at path.
func loadCRD(t *testing.T, path string) apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	_, body, _ := strings.Cut(string(raw), "---\n")
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict([]byte(body), &crd); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return crd
}

// populatedReport builds a Report with every field set, including optional ones.
func populatedReport(t *testing.T, grade, severity string) Report {
	t.Helper()
	r := &report.Report{
		Timestamp:  time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Clusters:   []string{"prod"},
		FleetScore: report.FleetScore{Score: 73, Grade: grade},
		Findings: []report.Finding{{
			Severity:    severity,
			Cluster:     "prod",
			Scanner:     "node-health",
			Title:       "node down",
			Description: "A node is not ready.",
			Affected:    []string{"node-1"},
			Remediation: &report.Remediation{
				Command:    "kubectl drain node-1",
				YAML:       "kind: Pod",
				RunbookURL: "https://example.com/runbook",
			},
		}},
	}
	reports := ReportsFor(r, "scan-1", "fleetsweeper")
	if len(reports) != 1 {
		t.Fatalf("want 1 report, got %d", len(reports))
	}
	return reports[0]
}

// toMap round-trips v through JSON into a generic map.
func toMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// missingPaths returns the key paths in value that the schema does not declare.
func missingPaths(path string, value any, schema apiextensionsv1.JSONSchemaProps) []string {
	switch v := value.(type) {
	case map[string]any:
		if len(schema.Properties) == 0 {
			if schema.AdditionalProperties != nil {
				return nil
			}
			return []string{path + " (no properties)"}
		}
		var out []string
		for key, child := range v {
			prop, ok := schema.Properties[key]
			if !ok {
				out = append(out, path+"."+key)
				continue
			}
			out = append(out, missingPaths(path+"."+key, child, prop)...)
		}
		return out
	case []any:
		if schema.Items == nil || schema.Items.Schema == nil {
			return []string{path + " (no items)"}
		}
		var out []string
		for _, child := range v {
			out = append(out, missingPaths(path+"[]", child, *schema.Items.Schema)...)
		}
		return out
	}
	return nil
}

// TestCRDSchemaCoversReport verifies every spec and status key a Report emits is declared in the
// CRD schema, since the API server prunes undeclared fields.
func TestCRDSchemaCoversReport(t *testing.T) {
	t.Parallel()
	crd := loadCRD(t, "../../deploy/crds/fleetdriftreport.yaml")
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	m := toMap(t, populatedReport(t, "C", "critical"))
	for _, section := range []string{"spec", "status"} {
		got := missingPaths(section, m[section], root.Properties[section])
		slices.Sort(got)
		if diff := cmp.Diff([]string(nil), got); diff != "" {
			t.Errorf("paths missing from CRD schema (-want +got):\n%s", diff)
		}
	}
}

// TestCRDEnums verifies grade and severity values the producer emits are in the CRD enums.
func TestCRDEnums(t *testing.T) {
	t.Parallel()
	crd := loadCRD(t, "../../deploy/crds/fleetdriftreport.yaml")
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	enumOf := func(s apiextensionsv1.JSONSchemaProps) []string {
		out := make([]string, 0, len(s.Enum))
		for _, raw := range s.Enum {
			var v string
			if err := json.Unmarshal(raw.Raw, &v); err != nil {
				t.Fatalf("enum value: %v", err)
			}
			out = append(out, v)
		}
		return out
	}
	grades := enumOf(root.Properties["spec"].Properties["fleetScore"].Properties["grade"])
	severities := enumOf(root.Properties["status"].Properties["findings"].Items.Schema.
		Properties["severity"])

	tests := []struct {
		WantEnum []string
		Enum     []string
		In       string
	}{{ // Test 0: Grades.
		Enum: grades, WantEnum: []string{"A", "B", "C", "D", "F"}, In: "grade",
	}, { // Test 1: Severities.
		Enum: severities, WantEnum: []string{"critical", "warning", "info"}, In: "severity",
	}}
	for _, test := range tests {
		t.Run(test.In, func(t *testing.T) {
			t.Parallel()
			for _, want := range test.WantEnum {
				if !slices.Contains(test.Enum, want) {
					t.Errorf("%s %q missing from CRD enum %v", test.In, want, test.Enum)
				}
			}
			for _, v := range test.WantEnum {
				var rep Report
				if test.In == "grade" {
					rep = populatedReport(t, v, "info")
					if !slices.Contains(test.Enum, rep.Spec.FleetScore.Grade) {
						t.Errorf("emitted grade %q not in enum", v)
					}
					continue
				}
				rep = populatedReport(t, "A", v)
				if !slices.Contains(test.Enum, rep.Status.Findings[0].Severity) {
					t.Errorf("emitted severity %q not in enum", v)
				}
			}
		})
	}
}

// TestFindingsRanked verifies findings sort by severity descending, then title.
func TestFindingsRanked(t *testing.T) {
	t.Parallel()
	got := toFindingSpecs([]report.Finding{
		{Severity: report.SeverityInfo, Title: "a"},
		{Severity: report.SeverityCritical, Title: "z"},
		{Severity: report.SeverityWarning, Title: "m"},
		{Severity: report.SeverityCritical, Title: "b"},
	})
	titles := make([]string, 0, len(got))
	for _, f := range got {
		titles = append(titles, f.Severity+":"+f.Title)
	}
	want := []string{"critical:b", "critical:z", "warning:m", "info:a"}
	if diff := cmp.Diff(want, titles); diff != "" {
		t.Errorf("order mismatch (-want +got):\n%s", diff)
	}
}
