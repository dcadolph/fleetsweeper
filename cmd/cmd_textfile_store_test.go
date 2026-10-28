package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestRunExportMetrics verifies the .prom file is written atomically with the
// expected metric names.
func TestRunExportMetrics(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "metrics.db")
	seedHistoryScans(t, dbPath, 1)
	outDir := filepath.Join(t.TempDir(), "textfile")

	cmd := newStoreCmd(dbPath)
	cmd.Flags().String("filename", "fleetsweeper.prom", "")
	if err := runExportMetrics(cmd, []string{outDir}); err != nil {
		t.Fatalf("export-metrics: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(outDir, "fleetsweeper.prom"))
	if err != nil {
		t.Fatalf("read prom: %v", err)
	}
	if !strings.Contains(string(body), "fleetsweeper_fleet_score") {
		t.Errorf("prom file missing fleet score metric:\n%s", body)
	}
}

// TestRunExportMetricsEmptyStore verifies an empty store is a clean error.
func TestRunExportMetricsEmptyStore(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	cmd := newStoreCmd(dbPath)
	cmd.Flags().String("filename", "fleetsweeper.prom", "")
	if err := runExportMetrics(cmd, []string{filepath.Join(t.TempDir(), "out")}); err == nil {
		t.Error("expected error when store has no scans")
	}
}
