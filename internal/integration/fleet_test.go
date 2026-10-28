//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

const (
	// outlierIdx is the index of the outlier cluster, cluster 5.
	outlierIdx = 4
	// sealKey signs the export bundle the test verifies.
	sealKey = "mock-fleet-seal"
)

// outlierRules are the fleet-relative rules the outlier's seed raises and no norm cluster
// carries: the cluster-admin grant to unauthenticated callers, the namespace left without a
// policy, and the orphan CRD. The outlier also carries rbac/outlier-cluster-role-count,
// rbac/outlier-cluster-role-binding-count, rbac-audit/outlier-wildcard-rules, and
// deprecated-apis/outlier-server-version from its older node image, so no assertion treats
// this list as the outlier's full rule set. The quota seed raises no rule, because no rule
// compares quota values across the fleet yet.
var outlierRules = []string{ //nolint:gochecknoglobals // Not modified.
	"rbac-audit/cluster-admin-binding",
	"network-policies/outlier-namespaces-without-policies",
	"crds/outlier-count",
}

// fixedRules are the outlier rules fixOutlier resolves.
var fixedRules = []string{ //nolint:gochecknoglobals // Not modified.
	"rbac-audit/cluster-admin-binding",
	"network-policies/outlier-namespaces-without-policies",
}

// persistingRules are the outlier rules fixOutlier leaves in place.
var persistingRules = []string{"crds/outlier-count"} //nolint:gochecknoglobals // Not modified.

// TestMockFleet stands up five kind clusters, four on the norm and the fifth an outlier on an
// older node image, tags clusters 3 and 4 into an edge cohort, scans through the built binary,
// fixes two of the outlier's differences, scans again, and asserts the findings, status,
// score, cohort, drift, and export end to end. Stock kind clusters carry absolute findings of
// their own (Pod Security labels, the privileged kube-proxy, bootstrap wildcard roles), so the
// assertions compare the outlier against the norm instead of expecting a clean norm.
func TestMockFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	start := time.Now()
	f := newFleet(t, "", "", "", "", imageOld)
	t.Logf("five clusters up in %s", time.Since(start).Round(time.Second))
	ctx := t.Context()
	for i := range outlierIdx {
		seedNorm(ctx, t, f.shapeClientsFor(t, i))
	}
	outlier := f.shapeClientsFor(t, outlierIdx)
	seedOutlier(ctx, t, outlier)

	contexts := f.Contexts()
	db := filepath.Join(t.TempDir(), "fleet.db")
	for _, i := range []int{2, 3} {
		mustCLI(t, f, "tag", "set", contexts[i], "cohort=edge", "--db", db)
	}

	first := scanFleet(t, f, db)
	dumpFindings(t, "first scan", first)
	t.Run("outlier carries its rules", func(t *testing.T) {
		got := rulesFor(first, contexts[outlierIdx])
		for _, rule := range outlierRules {
			if !slices.Contains(got, rule) {
				t.Errorf("outlier: want a %s finding, got %v", rule, got)
			}
		}
	})
	t.Run("norm clusters carry none of them", func(t *testing.T) {
		for i := range outlierIdx {
			got := rulesFor(first, contexts[i])
			for _, rule := range outlierRules {
				if slices.Contains(got, rule) {
					t.Errorf("norm cluster %d: want no %s finding, got %v", i+1, rule, got)
				}
			}
		}
	})
	t.Run("version skew marks only the outlier", func(t *testing.T) {
		i := slices.IndexFunc(first.Findings, func(f report.Finding) bool { return f.Rule == "version/skew" })
		if i < 0 {
			t.Fatal("no version/skew finding")
		}
		var marked []string
		for _, m := range first.Findings[i].Marks {
			marked = append(marked, m.Cluster)
		}
		if diff := cmp.Diff([]string{contexts[outlierIdx]}, marked); diff != "" {
			t.Errorf("version skew marks mismatch (-want +got):\n%s", diff)
		}
	})
	t.Run("outlier pays more than every norm cluster", func(t *testing.T) {
		outlierCtx := contexts[outlierIdx]
		if got := statusOf(first, outlierCtx); got != "critical" && got != "degraded" {
			t.Errorf("outlier: want critical or degraded, got %q", got)
		}
		want := charges(first, outlierCtx)
		for i := range outlierIdx {
			if got := charges(first, contexts[i]); got >= want {
				t.Errorf("norm cluster %d: %d critical plus warning charges, want fewer than the outlier's %d",
					i+1, got, want)
			}
		}
	})
	t.Run("healthy status implies no finding charge", func(t *testing.T) {
		assertStatusAgreesWithScore(t, first)
	})
	t.Run("edge cohort holds clusters 3 and 4", func(t *testing.T) {
		i := slices.IndexFunc(first.Cohorts, func(c report.CohortSummary) bool { return c.Name == "edge" })
		if i < 0 {
			t.Fatalf("no edge cohort; cohorts: %+v", first.Cohorts)
		}
		got := slices.Clone(first.Cohorts[i].Clusters)
		sort.Strings(got)
		if diff := cmp.Diff([]string{contexts[2], contexts[3]}, got); diff != "" {
			t.Errorf("edge cohort mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("html report renders", func(t *testing.T) {
		html, err := report.RenderHTML(first)
		if err != nil {
			t.Fatalf("render html: %v", err)
		}
		for _, want := range []string{"Fleetsweeper", contexts[outlierIdx]} {
			if !strings.Contains(string(html), want) {
				t.Errorf("HTML report lacks %q", want)
			}
		}
	})

	fixOutlier(ctx, t, outlier)
	second := scanFleet(t, f, db)
	dumpFindings(t, "second scan", second)
	t.Run("drift resolves the fixes and keeps the rest", func(t *testing.T) {
		diff := compareScans(t, f, db)
		outlierCtx := contexts[outlierIdx]
		for _, rule := range fixedRules {
			if !slices.Contains(diff.resolvedFor(outlierCtx), rule) {
				t.Errorf("want %s resolved on the outlier; resolved: %v", rule, diff.resolvedFor(outlierCtx))
			}
		}
		for _, rule := range persistingRules {
			if !slices.Contains(diff.persistedFor(outlierCtx), rule) {
				t.Errorf("want %s to persist on the outlier; persisted: %v", rule, diff.persistedFor(outlierCtx))
			}
			if slices.Contains(diff.resolvedFor(outlierCtx), rule) {
				t.Errorf("want %s not resolved; resolved: %v", rule, diff.resolvedFor(outlierCtx))
			}
		}
	})
	t.Run("second scan status agrees with score", func(t *testing.T) {
		assertStatusAgreesWithScore(t, second)
	})
	t.Run("export of the second scan verifies", func(t *testing.T) {
		bundle := filepath.Join(t.TempDir(), "scan.tar.gz")
		mustCLI(t, f, "export", "--db", db, "--scan-id", "latest", "--seal-key", sealKey, "--output", bundle)
		mustCLI(t, f, "verify", bundle, "--seal-key", sealKey)
		if res := f.runCLI(t, "verify", bundle, "--seal-key", "wrong-key"); res.Exit == 0 {
			t.Error("verify with the wrong key: want a nonzero exit")
		}
	})
	t.Logf("mock fleet test took %s", time.Since(start).Round(time.Second))
}

// mustCLI runs the binary and fails the test on a nonzero exit.
func mustCLI(t *testing.T, f *fleet, args ...string) cliResult {
	t.Helper()
	res := f.runCLI(t, args...)
	if res.Exit != 0 {
		t.Fatalf("fleetsweeper %s: exit %d\nstderr: %s", strings.Join(args, " "), res.Exit, res.Stderr)
	}
	return res
}

// scanFleet scans every fleet context into db through the binary and decodes the report.
func scanFleet(t *testing.T, f *fleet, db string) *report.Report {
	t.Helper()
	start := time.Now()
	res := mustCLI(t, f, "scan", "--all-contexts", "--db", db)
	var rpt report.Report
	if err := json.Unmarshal([]byte(res.Stdout), &rpt); err != nil {
		t.Fatalf("decode scan report: %v", err)
	}
	t.Logf("scan took %s", time.Since(start).Round(time.Second))
	return &rpt
}

// scanDiff is the part of `fleetsweeper compare --format json` the test reads.
type scanDiff struct {
	// Resolved lists findings present in the first scan and gone in the second.
	Resolved []report.Finding `json:"resolved"`
	// Persisted lists findings present in both scans.
	Persisted []report.Finding `json:"persisted"`
	// Drift is the drift ledger across the two scans.
	Drift report.Ledger `json:"drift"`
}

// resolvedFor returns the rules of resolved findings on cluster.
func (d scanDiff) resolvedFor(cluster string) []string {
	return rulesOn(d.Resolved, cluster)
}

// persistedFor returns the rules of persisted findings on cluster.
func (d scanDiff) persistedFor(cluster string) []string {
	return rulesOn(d.Persisted, cluster)
}

// rulesOn returns the rules of the findings on cluster.
func rulesOn(findings []report.Finding, cluster string) []string {
	var out []string
	for _, f := range findings {
		if f.Cluster == cluster {
			out = append(out, f.Rule)
		}
	}
	sort.Strings(out)
	return out
}

// compareScans diffs the previous and latest scans in db through the binary.
func compareScans(t *testing.T, f *fleet, db string) scanDiff {
	t.Helper()
	res := mustCLI(t, f, "compare", "previous", "latest", "--format", "json", "--db", db)
	var d scanDiff
	if err := json.Unmarshal([]byte(res.Stdout), &d); err != nil {
		t.Fatalf("decode compare: %v\n%s", err, res.Stdout)
	}
	return d
}

// rulesFor returns the rules of every finding on cluster.
func rulesFor(r *report.Report, cluster string) []string {
	return rulesOn(r.Findings, cluster)
}

// charges returns the critical plus warning findings cluster pays for in its score.
func charges(r *report.Report, cluster string) int {
	crit, warn := report.ClusterCharges(cluster, r.Findings)
	return crit + warn
}

// statusOf returns the status the report gives cluster.
func statusOf(r *report.Report, cluster string) string {
	for _, h := range r.ClusterHealths {
		if h.Name == cluster {
			return h.Status
		}
	}
	return ""
}

// assertStatusAgreesWithScore checks that every healthy cluster's score equals the score it
// would have with no findings at all, so no finding charged it.
func assertStatusAgreesWithScore(t *testing.T, r *report.Report) {
	t.Helper()
	for _, h := range r.ClusterHealths {
		charged := report.ComputeClusterScore(h, r.Findings).Score != report.ComputeClusterScore(h, nil).Score
		if h.Status == "healthy" && charged {
			t.Errorf("%s: status healthy but its score charges findings", h.Name)
		}
	}
}

// dumpFindings logs every finding by cluster, and writes the report to FLEET_DUMP when set,
// so a failing run shows what the real scanners saw.
func dumpFindings(t *testing.T, label string, r *report.Report) {
	t.Helper()
	var b strings.Builder
	for _, f := range r.Findings {
		var marks []string
		for _, m := range f.Marks {
			marks = append(marks, m.Cluster+"="+m.Severity)
		}
		fmt.Fprintf(&b, "\n  %-28s %-8s %-48s %v", f.Cluster, f.Severity, f.Rule, marks)
	}
	for _, h := range r.ClusterHealths {
		fmt.Fprintf(&b, "\n  status %-28s %s", h.Name, h.Status)
	}
	t.Logf("%s findings:%s", label, b.String())
	if dir := os.Getenv("FLEET_DUMP"); dir != "" {
		raw, _ := json.MarshalIndent(r, "", "  ")
		name := strings.ReplaceAll(label, " ", "-") + ".json"
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Logf("warning: dump %s: %v", name, err)
		}
	}
}
