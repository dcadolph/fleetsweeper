package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestResolveScans verifies the zero, one, and two argument forms plus the
// too-few-scans error.
func TestResolveScans(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "wc.db")
	ids := seedHistoryScans(t, dbPath, 2)
	idSet := map[string]bool{ids[0]: true, ids[1]: true}

	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	// Two args pass through in order.
	a, b, err := resolveScans(ctx, s, []string{"x", "y"})
	if err != nil || a != "x" || b != "y" {
		t.Fatalf("two-arg: (%q,%q) err=%v", a, b, err)
	}

	// One arg pairs against the latest scan.
	a, b, err = resolveScans(ctx, s, []string{"x"})
	if err != nil || a != "x" || !idSet[b] {
		t.Fatalf("one-arg: (%q,%q) err=%v", a, b, err)
	}

	// Zero args pairs the two most recent, distinct scans.
	a, b, err = resolveScans(ctx, s, nil)
	if err != nil || !idSet[a] || !idSet[b] || a == b {
		t.Fatalf("zero-arg: (%q,%q) err=%v", a, b, err)
	}
}

// TestResolveScansTooFew verifies the zero-arg form errors with one scan.
func TestResolveScansTooFew(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "wc.db")
	seedHistoryScans(t, dbPath, 1)
	s, _ := store.NewSQLite(dbPath)
	defer s.Close()
	if _, _, err := resolveScans(context.Background(), s, nil); err == nil {
		t.Error("expected error pairing latest two with one scan")
	}
}

// TestLatestScanID verifies the happy path and the empty-store error.
func TestLatestScanID(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "wc.db")
	ids := seedHistoryScans(t, dbPath, 1)
	s, _ := store.NewSQLite(dbPath)
	defer s.Close()
	got, err := latestScanID(context.Background(), s)
	if err != nil || got != ids[0] {
		t.Fatalf("latest: got %q err=%v", got, err)
	}

	empty, _ := store.NewSQLite(filepath.Join(t.TempDir(), "empty.db"))
	defer empty.Close()
	if _, err := latestScanID(context.Background(), empty); err == nil {
		t.Error("expected error on empty store")
	}
}

// TestBuildReportStore verifies a stored scan rebuilds and a bad id errors.
func TestBuildReportStore(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "wc.db")
	ids := seedHistoryScans(t, dbPath, 1)
	s, _ := store.NewSQLite(dbPath)
	defer s.Close()

	rpt, err := buildReport(context.Background(), s, ids[0])
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if len(rpt.Clusters) != 1 {
		t.Errorf("clusters: %v", rpt.Clusters)
	}
	if _, err := buildReport(context.Background(), s, "nope"); err == nil {
		t.Error("expected error for unknown scan id")
	}
}

// execWhatChanged executes the whatchanged subcommand and captures its output,
// which is written through cmd.OutOrStdout().
func execWhatChanged(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"whatchanged"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestWhatChangedRuns verifies both text and JSON rendering execute end to end.
func TestWhatChangedRuns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wc.db")
	seedHistoryScans(t, dbPath, 2)

	out, err := execWhatChanged(t, dbPath, "--json=false", "--severity=")
	if err != nil {
		t.Fatalf("text: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Fleet score") {
		t.Errorf("text output missing fleet score line:\n%s", out)
	}

	jsonOut, err := execWhatChanged(t, dbPath, "--json=true", "--severity=")
	if err != nil {
		t.Fatalf("json: %v\n%s", err, jsonOut)
	}
	if !strings.Contains(jsonOut, "fleet_score_delta") {
		t.Errorf("json output missing delta field:\n%s", jsonOut)
	}
}
