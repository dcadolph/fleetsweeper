package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestParseRetentionDuration verifies day and year suffixes plus the standard
// time.ParseDuration fallthrough and the error cases.
func TestParseRetentionDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In      string
		WantDur time.Duration
		Want    error
	}{
		{In: "30d", WantDur: 30 * 24 * time.Hour},  // Test 0: Day suffix.
		{In: "1y", WantDur: 365 * 24 * time.Hour},  // Test 1: Year suffix.
		{In: "24h", WantDur: 24 * time.Hour},       // Test 2: Standard duration.
		{In: "  7d ", WantDur: 7 * 24 * time.Hour}, // Test 3: Trimmed whitespace.
		{In: "", Want: errParse},                   // Test 4: Empty is an error.
		{In: "xd", Want: errParse},                 // Test 5: Non-numeric days.
		{In: "abc", Want: errParse},                // Test 6: Unparseable duration.
	}
	for testNum, test := range tests {
		t.Run(test.In, func(t *testing.T) {
			t.Parallel()
			got, err := parseRetentionDuration(test.In)
			if test.Want != nil {
				if err == nil {
					t.Fatalf("test %d: want error, got nil", testNum)
				}
				return
			}
			if err != nil {
				t.Fatalf("test %d: unexpected error: %v", testNum, err)
			}
			if got != test.WantDur {
				t.Errorf("test %d: got %s, want %s", testNum, got, test.WantDur)
			}
		})
	}
}

// errParse is a sentinel used only to flag that a test row expects any error.
var errParse = errors.New("parse")

// TestToSet verifies slice-to-set conversion collapses duplicates.
func TestToSet(t *testing.T) {
	t.Parallel()
	got := toSet([]string{"a", "b", "a"})
	if len(got) != 2 {
		t.Fatalf("want 2 members, got %d", len(got))
	}
	if _, ok := got["a"]; !ok {
		t.Error("missing member a")
	}
}

// TestFindingSet verifies findings are keyed by their identity tuple.
func TestFindingSet(t *testing.T) {
	t.Parallel()
	f1 := report.Finding{Severity: "critical", Cluster: "a", Scanner: "s", Title: "t1"}
	f2 := report.Finding{Severity: "warning", Cluster: "a", Scanner: "s", Title: "t2"}
	got := findingSet([]report.Finding{f1, f2})
	if len(got) != 2 {
		t.Fatalf("want 2 keys, got %d", len(got))
	}
	if _, ok := got["critical|a|s|t1"]; !ok {
		t.Errorf("missing expected key, got %v", got)
	}
}

// TestBuildScanDiff verifies cluster add/remove, summary deltas, and
// added/resolved findings between two reports.
func TestBuildScanDiff(t *testing.T) {
	t.Parallel()
	a := &report.Report{
		Clusters: []string{"a", "b"},
		Summary:  report.Summary{ClusterCount: 2, CriticalCount: 2, WarningCount: 1},
		Findings: []report.Finding{{Severity: "critical", Cluster: "a", Scanner: "s", Title: "gone"}},
	}
	b := &report.Report{
		Clusters: []string{"a", "c"},
		Summary:  report.Summary{ClusterCount: 2, CriticalCount: 1, WarningCount: 3},
		Findings: []report.Finding{{Severity: "warning", Cluster: "c", Scanner: "s", Title: "new"}},
	}
	d := buildScanDiff("idA", "idB", a, b)

	if diff := cmp.Diff([]string{"c"}, d.ClustersAdded, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("added mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"b"}, d.ClustersRemoved, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("removed mismatch (-want +got):\n%s", diff)
	}
	if d.SummaryDelta["critical_count"] != -1 || d.SummaryDelta["warning_count"] != 2 {
		t.Errorf("summary delta: %+v", d.SummaryDelta)
	}
	if len(d.FindingsAdded) != 1 || d.FindingsAdded[0].Title != "new" {
		t.Errorf("findings added: %+v", d.FindingsAdded)
	}
	if len(d.FindingsResolved) != 1 || d.FindingsResolved[0].Title != "gone" {
		t.Errorf("findings resolved: %+v", d.FindingsResolved)
	}
}

// seedHistoryScans saves n scans into a fresh SQLite DB and returns their IDs
// in save order.
func seedHistoryScans(t *testing.T, dbPath string, n int) []string {
	t.Helper()
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		results := map[string]map[string]scanner.Result{
			"prod": {"version": {Scanner: "version", Data: map[string]any{"server": i}}},
		}
		id, err := s.SaveScan(ctx, []string{"prod"}, results)
		if err != nil {
			t.Fatalf("save scan %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	return ids
}

// runHistory executes the history subcommand against a temp DB. The history
// bodies write their JSON to os.Stdout rather than cmd.OutOrStdout(), so tests
// assert on the returned error and store side-effects, not captured output.
func runHistory(t *testing.T, dbPath string, args ...string) error {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"history"}, args...)
	// Always pass --db explicitly. The shared rootCmd retains flag values
	// between Execute calls, so an empty path must override any leaked value.
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	return rootCmd.Execute()
}

// TestHistoryListShowDiff verifies the read paths run without error against a
// seeded store.
func TestHistoryListShowDiff(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hist.db")
	ids := seedHistoryScans(t, dbPath, 2)

	if err := runHistory(t, dbPath, "list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := runHistory(t, dbPath, "show", ids[0]); err != nil {
		t.Fatalf("show: %v", err)
	}
	if err := runHistory(t, dbPath, "diff", ids[0], ids[1]); err != nil {
		t.Fatalf("diff: %v", err)
	}
}

// TestHistoryShowMissingScan verifies a bad scan ID surfaces an error.
func TestHistoryShowMissingScan(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hist.db")
	seedHistoryScans(t, dbPath, 1)
	if err := runHistory(t, dbPath, "show", "does-not-exist"); err == nil {
		t.Error("expected error for unknown scan id")
	}
}

// TestHistoryPruneDryRun verifies dry-run leaves the scans in place.
func TestHistoryPruneDryRun(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hist.db")
	seedHistoryScans(t, dbPath, 2)
	if err := runHistory(t, dbPath, "prune", "--older-than=1d", "--dry-run=true", "--vacuum=false"); err != nil {
		t.Fatalf("prune dry-run: %v", err)
	}
	if n := countScans(t, dbPath); n != 2 {
		t.Errorf("dry-run must not delete: got %d scans, want 2", n)
	}
}

// TestHistoryPruneDeletes verifies a real prune removes every stale scan. A
// negative --older-than places the cutoff in the future so the just-seeded
// scans qualify deterministically.
func TestHistoryPruneDeletes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hist.db")
	seedHistoryScans(t, dbPath, 2)
	if err := runHistory(t, dbPath, "prune", "--older-than=-1h", "--dry-run=false", "--vacuum=true"); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n := countScans(t, dbPath); n != 0 {
		t.Errorf("prune should have emptied the store, got %d scans", n)
	}
}

// TestHistoryTrend verifies trend runs with a single scan (graceful) and with
// two scans (full computation).
func TestHistoryTrend(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hist.db")
	seedHistoryScans(t, dbPath, 1)
	if err := runHistory(t, dbPath, "trend"); err != nil {
		t.Fatalf("trend one-scan: %v", err)
	}
	seedHistoryScans(t, dbPath, 2)
	if err := runHistory(t, dbPath, "trend", "--cluster=prod"); err != nil {
		t.Fatalf("trend two-scan: %v", err)
	}
}

// TestHistoryRequiresDB verifies the missing-db sentinel surfaces.
func TestHistoryRequiresDB(t *testing.T) {
	if err := runHistory(t, "", "list"); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("want ErrNoDatabase, got %v", err)
	}
}

// countScans reopens the store and returns the number of persisted scans.
func countScans(t *testing.T, dbPath string) int {
	t.Helper()
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	scans, err := s.ListScans(context.Background(), 100)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	return len(scans)
}
