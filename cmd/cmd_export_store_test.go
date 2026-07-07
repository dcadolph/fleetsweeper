package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// execExport runs the export subcommand against a temp DB.
func execExport(t *testing.T, dbPath string, args ...string) error {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"export"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	return rootCmd.Execute()
}

// TestRunExportToFile verifies export writes a non-empty bundle for the latest
// scan, both plain and sealed.
func TestRunExportToFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exp.db")
	seedHistoryScans(t, dbPath, 1)

	plain := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := execExport(t, dbPath, "--scan-id=latest", "--output="+plain, "--seal-key="); err != nil {
		t.Fatalf("export plain: %v", err)
	}
	if fi, err := os.Stat(plain); err != nil || fi.Size() == 0 {
		t.Fatalf("plain bundle missing or empty: %v", err)
	}

	sealed := filepath.Join(t.TempDir(), "sealed.tar.gz")
	if err := execExport(t, dbPath, "--scan-id=latest", "--output="+sealed, "--seal-key=secret"); err != nil {
		t.Fatalf("export sealed: %v", err)
	}
	if fi, err := os.Stat(sealed); err != nil || fi.Size() == 0 {
		t.Fatalf("sealed bundle missing or empty: %v", err)
	}
}

// TestRunExportEmptyStore verifies the no-scans error path.
func TestRunExportEmptyStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	if err := execExport(t, dbPath, "--scan-id=latest", "--output=", "--seal-key="); err == nil {
		t.Error("expected error when store has no scans")
	}
}
