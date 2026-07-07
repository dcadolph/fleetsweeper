package report

import (
	"testing"
)

// TestFuseIncidents verifies that correlated findings on one cluster fuse into a
// single incident carrying the max severity, while unrelated or lone findings
// are left out.
func TestFuseIncidents(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		// prod-east: three node-pressure signals -> one incident.
		{Title: "prod-east has 2 nodes under memory pressure", Severity: SeverityCritical, Cluster: "prod-east", Scanner: "node-health"},
		{Title: "prod-east CPU is high", Severity: SeverityWarning, Cluster: "prod-east", Scanner: "metrics"},
		{Title: "prod-east warning-event spike", Severity: SeverityWarning, Cluster: "prod-east", Scanner: "events"},
		// prod-east: a lone security finding -> not an incident (needs >= 2).
		{Title: "prod-east has a privileged container", Severity: SeverityWarning, Cluster: "prod-east", Scanner: "workload-security"},
		// staging: a single admission finding -> no incident.
		{Title: "staging webhook has no endpoints", Severity: SeverityCritical, Cluster: "staging", Scanner: "admission"},
		// fleet-scoped finding -> ignored.
		{Title: "fleet version skew", Severity: SeverityWarning, Cluster: "fleet", Scanner: "version"},
	}

	got := FuseIncidents(findings)

	// Test 0: exactly one incident (the node-pressure trio).
	if len(got) != 1 {
		t.Fatalf("got %d incidents, want 1: %+v", len(got), got)
	}
	inc := got[0]
	if inc.Cluster != "prod-east" || inc.Theme != "node-pressure" {
		t.Errorf("incident = %s/%s, want prod-east/node-pressure", inc.Cluster, inc.Theme)
	}
	if inc.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical (max of members)", inc.Severity)
	}
	if len(inc.Findings) != 3 {
		t.Errorf("fused %d findings, want 3", len(inc.Findings))
	}
	if inc.Summary == "" {
		t.Error("incident summary should not be empty")
	}
}
