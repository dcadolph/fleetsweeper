package server

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoTestNow is when the newest scan of the test demo fleet runs.
var demoTestNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) //nolint:gochecknoglobals // Not modified, simplifies testing.

// demoTestReport builds the newest demo scan's report with the options the demo server uses:
// cohort tags and groups.
func demoTestReport() *report.Report {
	groups := map[string][]string{}
	for _, g := range demoGroups() {
		groups[g.Name] = g.Clusters
	}
	opts := report.BuildOptions{ClusterTags: demoTags(), Groups: groups, Timestamp: demoTestNow}
	return report.Build(demoClusterNames(), demoResults(demoScans-1, demoTestNow, demoTestNow), opts)
}

// TestDemoReportRunsRealEngine verifies that serve --demo exercises the real
// report engine: the synthetic fleet produces populated per-scanner sections,
// fleet-level outliers, cohorts, and degraded coverage, rather than hand-faked
// data with an empty Sections map.
func TestDemoReportRunsRealEngine(t *testing.T) {
	t.Parallel()

	r := demoTestReport()

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
		t.Error("expected findings from the planted incidents")
	}
}

// TestDemoFindingsCarryRules verifies every demo finding has a cataloged rule
// and a unique fingerprint derived from it, and every norm finding carries a
// remediation that states the gap.
func TestDemoFindingsCarryRules(t *testing.T) {
	t.Parallel()

	normScanners := map[string]bool{"security": true, "metrics": true, "events": true, "namespaces": true}
	seen := map[string]string{}
	for _, f := range demoTestReport().Findings {
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
	clusters := demoClusterNames()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	opts := report.BuildOptions{ClusterTags: demoTags(), Timestamp: at}
	render := func() []byte {
		r := report.Build(clusters, demoResults(demoScans-1, at, at), opts)
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

// TestDemoScoreReconciles verifies the demo report's score ledger counts the
// same findings the report lists.
func TestDemoScoreReconciles(t *testing.T) {
	t.Parallel()
	r := demoTestReport()
	count := map[string]int{}
	for _, f := range r.Findings {
		count[f.Severity]++
	}
	terms := map[string]string{
		"critical-findings": report.SeverityCritical,
		"warning-findings":  report.SeverityWarning,
		"info-findings":     report.SeverityInfo,
	}
	for _, term := range r.ScoreAttribution.Terms {
		if sev, ok := terms[term.Term]; ok && term.Count != count[sev] {
			t.Errorf("%s counts %d, report lists %d", term.Term, term.Count, count[sev])
		}
	}
	if math.Abs(100-r.ScoreAttribution.Total-float64(r.FleetScore.Score)) > 0.5 && r.ScoreAttribution.Total < 100 {
		t.Errorf("100 - ledger total %v is not score %d", r.ScoreAttribution.Total, r.FleetScore.Score)
	}
}

// TestSeedDemo verifies the seed fills an empty store with the demo series, alerts, tags,
// groups, and manual locations, and that seeding a store that holds scans changes nothing.
func TestSeedDemo(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	st := srv.store
	ctx := t.Context()
	if err := SeedDemo(ctx, st, demoTestNow.Add(time.Hour)); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	scans, err := st.ListScans(ctx, 100)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	alerts, err := st.ListAlerts(ctx, store.AlertListOptions{})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	groups, err := st.ListGroups(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	locations, err := st.ListLocations(ctx)
	if err != nil {
		t.Fatalf("list locations: %v", err)
	}
	tags, err := st.ListClusterTags(ctx)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	manual := 0
	for _, c := range demoFleet() {
		if c.Source == "manual" {
			manual++
		}
	}
	got := []int{len(scans), len(scans[0].Clusters), len(alerts), len(groups), len(locations), len(tags)}
	want := []int{demoScans, len(demoFleet()), len(demoAlerts(demoTestNow)), 4, manual, len(demoFleet())}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("seeded counts mismatch (scans, clusters, alerts, groups, locations, tags) (-want +got):\n%s", diff)
	}
	if !scans[0].Timestamp.Equal(demoTestNow) {
		t.Errorf("newest scan at %v, want %v: the second seed must not run", scans[0].Timestamp, demoTestNow)
	}
}

// TestDemoScoreBand verifies the newest demo scan scores between 60 and 85 with three drivers
// from three different terms, and the oldest scores higher, so history shows a decline.
func TestDemoScoreBand(t *testing.T) {
	t.Parallel()
	r := demoTestReport()
	if s := r.FleetScore.Score; s < 60 || s > 85 {
		t.Errorf("demo score %d, want 60 to 85", s)
	}
	terms := map[string]bool{}
	for _, d := range r.ScoreAttribution.Drivers() {
		terms[d.Reason] = true
	}
	if len(r.FleetScore.Drivers) != 3 || len(terms) != 3 {
		t.Errorf("drivers %+v, want three distinct", r.FleetScore.Drivers)
	}
	groups := map[string][]string{}
	for _, g := range demoGroups() {
		groups[g.Name] = g.Clusters
	}
	start := demoTestNow.Add(-time.Duration(demoScans-1) * demoStep)
	oldest := report.Build(demoClusterNames(), demoResults(0, start, demoTestNow),
		report.BuildOptions{ClusterTags: demoTags(), Groups: groups, Timestamp: start})
	if oldest.FleetScore.Score <= r.FleetScore.Score {
		t.Errorf("oldest scan scores %d, newest %d: want a decline", oldest.FleetScore.Score, r.FleetScore.Score)
	}
}
