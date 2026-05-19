package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestBackupRestoreRoundTrip writes a tiny scan to a SQLite database,
// runs the backup command, deletes the original, runs restore, and verifies
// the scan is still queryable.
func TestBackupRestoreRoundTrip(t *testing.T) {
	t.Parallel()
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
