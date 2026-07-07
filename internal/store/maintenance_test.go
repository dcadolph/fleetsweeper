package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// backdateScan rewrites a scan's stored timestamp so time-range and prune tests
// are deterministic without sleeping.
func backdateScan(t *testing.T, s *SQLite, id string, ts time.Time) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE scans SET timestamp = ? WHERE id = ?", ts.UTC().Format(time.RFC3339), id)
	if err != nil {
		t.Fatalf("backdate scan %s: %v", id, err)
	}
}

// saveOneScan persists a single-cluster scan and returns its ID.
func saveOneScan(t *testing.T, s *SQLite, cluster string) string {
	t.Helper()
	results := map[string]map[string]scanner.Result{
		cluster: {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
	id, err := s.SaveScan(context.Background(), []string{cluster}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	return id
}

// TestPrune verifies scans older than the cutoff are deleted, their result rows
// cascade, and newer scans are retained.
func TestPrune(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	oldID := saveOneScan(t, s, "old-cluster")
	newID := saveOneScan(t, s, "new-cluster")
	backdateScan(t, s, oldID, base.Add(-72*time.Hour))
	backdateScan(t, s, newID, base)

	n, err := s.Prune(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if diff := cmp.Diff(1, n); diff != "" {
		t.Errorf("pruned count (-want +got):\n%s", diff)
	}

	// The surviving scan is still fetchable.
	if _, err := s.GetScan(ctx, newID); err != nil {
		t.Errorf("new scan should survive: %v", err)
	}

	// Cascade: the pruned scan's result rows are gone.
	res, err := s.GetScanResults(ctx, oldID)
	if err != nil {
		t.Fatalf("get pruned results: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected scan_results to cascade-delete, got %+v", res)
	}
}

// TestVacuum verifies VACUUM runs without error on a populated database.
func TestVacuum(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	saveOneScan(t, s, "c")
	if err := s.Vacuum(context.Background()); err != nil {
		t.Errorf("vacuum: %v", err)
	}
}

// TestVacuumInto verifies the snapshot path is validated and a snapshot file is
// written to a fresh path.
func TestVacuumInto(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	saveOneScan(t, s, "c")
	ctx := context.Background()

	if err := s.VacuumInto(ctx, ""); err == nil {
		t.Error("empty path: expected an error")
	}

	dst := filepath.Join(t.TempDir(), "snapshot.db")
	if err := s.VacuumInto(ctx, dst); err != nil {
		t.Fatalf("vacuum into: %v", err)
	}
	if info, err := os.Stat(dst); err != nil || info.Size() == 0 {
		t.Errorf("expected a non-empty snapshot at %s (err=%v)", dst, err)
	}
}

// TestGetScansByTimeRange verifies the inclusive time-window filter.
func TestGetScansByTimeRange(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	before := saveOneScan(t, s, "before")
	inside := saveOneScan(t, s, "inside")
	after := saveOneScan(t, s, "after")
	backdateScan(t, s, before, base.Add(-10*time.Hour))
	backdateScan(t, s, inside, base)
	backdateScan(t, s, after, base.Add(10*time.Hour))

	got, err := s.GetScansByTimeRange(ctx, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(got) != 1 || got[0].ID != inside {
		t.Errorf("expected only the in-window scan; got %+v", got)
	}
}

// TestPing verifies connectivity checks succeed on an open store.
func TestPing(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Errorf("ping open store: %v", err)
	}
}
