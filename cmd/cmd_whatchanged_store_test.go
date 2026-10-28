package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
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

// seedStepScans stores six scans of a 10-cluster fleet an hour apart, IDs
// scan-1 to scan-6, with c04 stepping from 24 to 80 enforced namespaces at
// scan-4.
func seedStepScans(t *testing.T, dbPath string) {
	t.Helper()
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	base := []float64{20, 22, 23, 24, 24, 25, 26, 26, 28, 30}
	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	for n := 1; n <= 6; n++ {
		clusters := make([]string, 0, len(base))
		results := map[string]map[string]scanner.Result{}
		for i, v := range base {
			c := fmt.Sprintf("c%02d", i)
			if c == "c04" && n >= 4 {
				v = 80
			}
			clusters = append(clusters, c)
			results[c] = map[string]scanner.Result{"security": {Scanner: "security", Data: map[string]any{"enforced_count": v}}}
		}
		rec := store.ScanRecord{ID: fmt.Sprintf("scan-%d", n), Timestamp: start.Add(time.Duration(n) * time.Hour), Clusters: clusters}
		if _, err := s.SaveScanRecord(context.Background(), rec, results); err != nil {
			t.Fatalf("save scan %d: %v", n, err)
		}
	}
}

// TestWhatChangedDrift verifies whatchanged reads every scan between the two
// it compares, so the drifted cluster leads the ledger with its flag stamped
// with the scan it flipped in, and the text lists drift above the findings.
func TestWhatChangedDrift(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "drift.db")
	seedStepScans(t, dbPath)

	jsonOut, err := execWhatChanged(t, dbPath, "scan-1", "scan-6", "--json=true", "--severity=")
	if err != nil {
		t.Fatalf("json: %v\n%s", err, jsonOut)
	}
	var diff whatChangedDiff
	if err := json.Unmarshal([]byte(jsonOut), &diff); err != nil {
		t.Fatalf("decode: %v\n%s", err, jsonOut)
	}
	if diff := cmp.Diff([]string{"scan-1", "scan-2", "scan-3", "scan-4", "scan-5", "scan-6"}, diff.Drift.Scans); diff != "" {
		t.Errorf("ledger scans mismatch (-want +got):\n%s", diff)
	}
	if len(diff.Drift.Clusters) == 0 || diff.Drift.Clusters[0].Cluster != "c04" {
		t.Fatalf("want c04 first in the ledger, got %+v", diff.Drift.Clusters)
	}
	want := []report.FlagChange{{Scanner: "security", Field: "enforced_count", Scan: "scan-4"}}
	if d := cmp.Diff(want, diff.Drift.Clusters[0].Gained); d != "" {
		t.Errorf("gained mismatch (-want +got):\n%s", d)
	}

	text, err := execWhatChanged(t, dbPath, "scan-1", "scan-6", "--json=false", "--severity=")
	if err != nil {
		t.Fatalf("text: %v\n%s", err, text)
	}
	if !strings.Contains(text, "now flagged on security/enforced_count since scan-4") {
		t.Errorf("text lacks the flag line:\n%s", text)
	}
	if strings.Index(text, "Drifted clusters") > strings.Index(text, "New findings") {
		t.Errorf("drift is not above the findings:\n%s", text)
	}
}
