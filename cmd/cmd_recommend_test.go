package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestBuildRecommendations_LeverageOrdering verifies the same
// remediation across many clusters outranks a more severe one with
// less leverage when the math works out that way.
func TestBuildRecommendations_LeverageOrdering(t *testing.T) {
	t.Parallel()
	findings := []report.Finding{
		// One critical finding with no leverage.
		{
			Title: "low-leverage critical", Severity: "critical",
			Cluster: "x", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl x"},
		},
		// One warning finding present on five clusters.
		{
			Title: "high-leverage warning", Severity: "warning",
			Cluster: "a", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl y"},
		},
		{
			Title: "high-leverage warning", Severity: "warning",
			Cluster: "b", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl y"},
		},
		{
			Title: "high-leverage warning", Severity: "warning",
			Cluster: "c", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl y"},
		},
		{
			Title: "high-leverage warning", Severity: "warning",
			Cluster: "d", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl y"},
		},
		{
			Title: "high-leverage warning", Severity: "warning",
			Cluster: "e", Scanner: "s",
			Remediation: &report.Remediation{Command: "kubectl y"},
		},
	}
	recs := buildRecommendations(findings, "")
	if len(recs) != 2 {
		t.Fatalf("want 2 recs, got %d", len(recs))
	}
	// 5 clusters * (warning+1) = 5*3 = 15
	// 1 cluster  * (critical+1) = 1*4 = 4
	// High-leverage warning should come first.
	if recs[0].Title != "high-leverage warning" {
		t.Errorf("first: want high-leverage, got %q", recs[0].Title)
	}
	if recs[0].Leverage != 5 {
		t.Errorf("leverage: want 5, got %d", recs[0].Leverage)
	}
}

// TestBuildRecommendations_SkipsFindingsWithoutRemediation verifies a
// finding lacking a Remediation pointer is excluded from the rollup.
func TestBuildRecommendations_SkipsFindingsWithoutRemediation(t *testing.T) {
	t.Parallel()
	recs := buildRecommendations([]report.Finding{
		{Title: "no-remediation", Severity: "critical", Scanner: "s", Cluster: "a"},
		{Title: "yes-remediation", Severity: "warning", Scanner: "s", Cluster: "a",
			Remediation: &report.Remediation{Command: "kubectl"}},
	}, "")
	if len(recs) != 1 || recs[0].Title != "yes-remediation" {
		t.Errorf("recs: %+v", recs)
	}
}

// TestBuildRecommendations_SeverityFilter verifies the minSeverity
// argument clips below-threshold findings.
func TestBuildRecommendations_SeverityFilter(t *testing.T) {
	t.Parallel()
	findings := []report.Finding{
		{Title: "i", Severity: "info", Scanner: "s", Cluster: "a", Remediation: &report.Remediation{Command: "x"}},
		{Title: "w", Severity: "warning", Scanner: "s", Cluster: "a", Remediation: &report.Remediation{Command: "x"}},
		{Title: "c", Severity: "critical", Scanner: "s", Cluster: "a", Remediation: &report.Remediation{Command: "x"}},
	}
	recs := buildRecommendations(findings, "warning")
	titles := map[string]bool{}
	for _, r := range recs {
		titles[r.Title] = true
	}
	if titles["i"] {
		t.Error("info should be filtered out")
	}
	if !titles["w"] || !titles["c"] {
		t.Errorf("warning+ missing: %v", titles)
	}
}

// TestBuildRecommendations_PromotesSeverityWithinGroup verifies the
// recommendation's Severity is the highest seen across contributing rows.
func TestBuildRecommendations_PromotesSeverityWithinGroup(t *testing.T) {
	t.Parallel()
	rem := &report.Remediation{Command: "kubectl"}
	findings := []report.Finding{
		{Title: "T", Scanner: "s", Cluster: "a", Severity: "warning", Remediation: rem},
		{Title: "T", Scanner: "s", Cluster: "b", Severity: "critical", Remediation: rem},
	}
	recs := buildRecommendations(findings, "")
	if len(recs) != 1 || recs[0].Severity != "critical" {
		t.Errorf("severity should promote to critical, got %+v", recs)
	}
}

// TestWriteRecommendations_HumanCoversCoreLines verifies the formatted
// output includes the leverage figure, the kubectl command, and an
// applied YAML block.
func TestWriteRecommendations_HumanCoversCoreLines(t *testing.T) {
	t.Parallel()
	recs := []recommendation{{
		Title:    "Add default-deny NetworkPolicy",
		Scanner:  "networkpolicy",
		Severity: "warning",
		Clusters: []string{"a", "b", "c"},
		Leverage: 3,
		Command:  "kubectl -n ns apply -f default-deny.yaml",
		YAML:     "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy",
	}}
	buf := &bytes.Buffer{}
	if err := writeRecommendations(buf, recs, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	wants := []string{
		"Leverage: 3 cluster(s)",
		"Run:      kubectl",
		"Apply:",
		"apiVersion: networking.k8s.io/v1",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// TestWriteRecommendations_EmptyPrintsExplicitMessage verifies an
// empty list is rendered with a clear message rather than silence.
func TestWriteRecommendations_EmptyPrintsExplicitMessage(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	if err := writeRecommendations(buf, nil, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "No actionable remediations") {
		t.Errorf("missing empty message: %s", buf.String())
	}
}

// TestWriteRecommendations_JSONRoundTrip confirms JSON emission decodes.
func TestWriteRecommendations_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	recs := []recommendation{{Title: "T", Leverage: 2, Clusters: []string{"a", "b"}}}
	buf := &bytes.Buffer{}
	if err := writeRecommendations(buf, recs, true); err != nil {
		t.Fatalf("render: %v", err)
	}
	var got []recommendation
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Title != "T" || got[0].Leverage != 2 {
		t.Errorf("decoded: %+v", got)
	}
}

// TestJoinTrim_ClipsLongLists verifies the cluster list summariser.
func TestJoinTrim_ClipsLongLists(t *testing.T) {
	t.Parallel()
	got := joinTrim([]string{"a", "b", "c", "d", "e", "f", "g"}, 3)
	if !strings.Contains(got, "(+4 more)") {
		t.Errorf("want clip suffix, got %q", got)
	}
}
