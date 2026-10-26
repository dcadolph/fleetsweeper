package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestBackupRestoreRoundTrip writes a tiny scan to a SQLite database,
// runs the backup command, deletes the original, runs restore, and verifies
// the scan is still queryable.
func TestBackupRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	defer lockRootCmd(t)()
	dir := t.TempDir()
	original := filepath.Join(dir, "fleet.db")
	snapshot := filepath.Join(dir, "snapshot.db")
	restored := filepath.Join(dir, "restored.db")

	src, err := store.NewSQLite(original)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	scanID, err := src.SaveScan(context.Background(),
		[]string{"prod-east"},
		map[string]map[string]scanner.Result{
			"prod-east": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
		})
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	src.Close()

	// Run backup.
	buf := &bytes.Buffer{}
	backupCmd.SetErr(buf)
	backupCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"backup",
		"--db=" + original,
		"--output=" + snapshot,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}

	// Run restore to a fresh path.
	rootCmd.SetArgs([]string{"restore", snapshot,
		"--db=" + restored,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Verify the restored database contains the scan.
	dst, err := store.NewSQLite(restored)
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer dst.Close()
	got, err := dst.GetScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("get scan from restored: %v", err)
	}
	if got.ID != scanID {
		t.Errorf("scan id mismatch: want %s got %s", scanID, got.ID)
	}
}

// TestBackupRejectsPostgresDSN verifies the backup command refuses Postgres
// DSNs with a clear message rather than trying to misbehave. Sequential
// (no t.Parallel) because rootCmd flag state is shared across tests.
func TestBackupRejectsPostgresDSN(t *testing.T) {
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	rootCmd.SetArgs([]string{"backup",
		"--db=postgres://example/db",
		"--output=/tmp/wont-write",
	})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("expected sqlite-only error, got %v", err)
	}
}

// seedScanDB creates a SQLite database at path holding one scan with the given ID.
func seedScanDB(t *testing.T, path, id string) {
	t.Helper()
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer s.Close()
	results := map[string]map[string]scanner.Result{
		"prod-east": {"version": {Scanner: "version", Data: map[string]any{"v": id}}},
	}
	if _, err := s.SaveScanRecord(context.Background(), store.ScanRecord{ID: id, Clusters: []string{"prod-east"}}, results); err != nil {
		t.Fatalf("save scan %s: %v", id, err)
	}
}

// execBackupCmd runs one backup or restore invocation on rootCmd. Callers pass every boolean
// flag explicitly because rootCmd keeps flag values across Execute calls.
func execBackupCmd(t *testing.T, args ...string) error {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

// scanIDs lists the scan IDs in the SQLite database at path.
func scanIDs(t *testing.T, path string) []string {
	t.Helper()
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer s.Close()
	scans, err := s.ListScans(context.Background(), 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	ids := make([]string, 0, len(scans))
	for _, sc := range scans {
		ids = append(ids, sc.ID)
	}
	return ids
}

// dirEntries returns the sorted file names in dir.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestRestoreReplacesStaleWAL verifies that restoring over a database that left a WAL behind
// yields exactly the snapshot. SQLite replays a -wal file onto whatever database file sits
// beside it, so a stale WAL must not survive the restore.
func TestRestoreReplacesStaleWAL(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fleet.db")
	snapDB := filepath.Join(dir, "source.db")
	snapshot := filepath.Join(dir, "snapshot.db.gz")

	seedScanDB(t, snapDB, "snap-1")
	if err := execBackupCmd(t, "backup", "--db="+snapDB, "--output="+snapshot, "--overwrite=false"); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Leave the target with a WAL that holds an uncheckpointed write, as a crashed server would.
	live, err := store.NewSQLite(target)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	if _, err := live.SaveScanRecord(context.Background(), store.ScanRecord{ID: "stale-1", Clusters: []string{"prod-east"}},
		map[string]map[string]scanner.Result{"prod-east": {"version": {Scanner: "version"}}}); err != nil {
		t.Fatalf("save stale scan: %v", err)
	}
	wal, err := os.ReadFile(target + "-wal")
	if err != nil || len(wal) == 0 {
		t.Fatalf("expected a live WAL beside the target: %v (%d bytes)", err, len(wal))
	}
	live.Close()
	if err := os.WriteFile(target+"-wal", wal, 0o600); err != nil {
		t.Fatalf("write stale wal: %v", err)
	}

	if err := execBackupCmd(t, "restore", snapshot, "--db="+target, "--force=true"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, p := range []string{target + "-wal", target + "-shm"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the restore: %v", filepath.Base(p), err)
		}
	}
	if diff := cmp.Diff([]string{"snap-1"}, scanIDs(t, target)); diff != "" {
		t.Errorf("restored scans mismatch (-want +got):\n%s", diff)
	}
}

// TestRestoreBadSnapshotLeavesTarget verifies that a snapshot that is not a database fails
// before anything replaces the target, and leaves no temporary files behind.
func TestRestoreBadSnapshotLeavesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fleet.db")
	seedScanDB(t, target, "keep-1")
	snapshot := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(snapshot, bytes.Repeat([]byte("not sqlite "), 512), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	before := dirEntries(t, dir)

	if err := execBackupCmd(t, "restore", snapshot, "--db="+target, "--force=true"); err == nil {
		t.Fatal("expected restore of a junk snapshot to fail")
	}
	if diff := cmp.Diff(before, dirEntries(t, dir)); diff != "" {
		t.Errorf("directory changed (-before +after):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"keep-1"}, scanIDs(t, target)); diff != "" {
		t.Errorf("target scans mismatch (-want +got):\n%s", diff)
	}
}

// TestRestoreRefusesWithoutForce verifies an existing database is not replaced without --force.
func TestRestoreRefusesWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fleet.db")
	seedScanDB(t, target, "keep-1")
	snapDB := filepath.Join(dir, "source.db")
	seedScanDB(t, snapDB, "snap-1")

	err := execBackupCmd(t, "restore", snapDB, "--db="+target, "--force=false")
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want a --force error, got %v", err)
	}
	if diff := cmp.Diff([]string{"keep-1"}, scanIDs(t, target)); diff != "" {
		t.Errorf("target scans mismatch (-want +got):\n%s", diff)
	}
}
