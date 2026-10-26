package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestDemoReportRunsRealEngine verifies that serve --demo exercises the real
// report engine: the synthetic fleet produces populated per-scanner sections,
// fleet-level outliers, cohorts, and degraded coverage, rather than hand-faked
// data with an empty Sections map.
func TestDemoReportRunsRealEngine(t *testing.T) {
	t.Parallel()

	r := demoReport()

	if len(r.Sections) == 0 {
		t.Fatal("demo report has no per-scanner sections; the outlier engine cannot run")
	}
	// The demo fleet has more than 20 clusters, so fleet-level MAD outliers fire.
	if len(r.Outliers) == 0 {
		t.Error("expected fleet-level outliers from the demo data")
	}
	if len(r.Cohorts) == 0 {
		t.Error("expected cohorts from the demo data")
	}
	// One scanner is planted as errored, so degraded coverage must surface
	// instead of a false all-clear.
	if len(r.Degraded) == 0 {
		t.Error("expected degraded coverage from the planted errored scanner")
	}
	if len(r.Findings) == 0 {
		t.Error("expected findings from the engine plus curated narratives")
	}
}

// TestDemoFindingsCarryRules verifies every demo finding has a cataloged rule
// and a unique fingerprint derived from it, and every norm finding carries a
// remediation that states the gap.
func TestDemoFindingsCarryRules(t *testing.T) {
	t.Parallel()

	normScanners := map[string]bool{"security": true, "metrics": true, "events": true, "namespaces": true}
	seen := map[string]string{}
	for _, f := range demoReport().Findings {
		if prev, dup := seen[f.Fingerprint]; dup {
			t.Errorf("findings %q and %q share fingerprint %s", prev, f.Title, f.Fingerprint)
		}
		seen[f.Fingerprint] = f.Title
		if f.Rule == "" || report.RuleTitle(f.Rule) == f.Rule {
			t.Errorf("finding %q has uncataloged rule %q", f.Title, f.Rule)
		}
		if f.Fingerprint != report.FindingFingerprint(f) {
			t.Errorf("finding %q fingerprint %q does not match its rule", f.Title, f.Fingerprint)
		}
		if strings.Contains(f.Title, "deviates") && f.Remediation == nil {
			t.Errorf("norm finding %q has no remediation", f.Title)
		}
		if normScanners[f.Scanner] && strings.Contains(f.Title, "deviates") && !strings.HasPrefix(f.Remediation.Command, "# ") {
			t.Errorf("norm finding %q remediation does not state the gap: %q", f.Title, f.Remediation.Command)
		}
	}
}

// TestBuildDeterministic verifies that rebuilding a report from the same results and timestamp
// yields the same JSON and HTML bytes every time, which sealing a stored scan depends on.
func TestBuildDeterministic(t *testing.T) {
	t.Parallel()
	var clusters []string
	for _, p := range demoPoints() {
		clusters = append(clusters, p.Cluster)
	}
	opts := report.BuildOptions{ClusterTags: demoTags(), Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	render := func() []byte {
		r := report.Build(clusters, demoResults(), opts)
		js, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		html, err := report.RenderHTML(r)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return append(js, html...)
	}
	want := render()
	for run := range 20 {
		if got := render(); !bytes.Equal(want, got) {
			t.Fatalf("run %d produced different bytes", run+1)
		}
	}
}
