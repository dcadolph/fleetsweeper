package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// execRecommend runs the recommend subcommand and captures its output.
func execRecommend(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"recommend"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestRecommendRuns verifies the recommend command runs against a seeded store.
func TestRecommendRuns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rec.db")
	seedHistoryScans(t, dbPath, 1)
	out, err := execRecommend(t, dbPath, "--json=false", "--severity=", "--limit=25")
	if err != nil {
		t.Fatalf("recommend: %v\n%s", err, out)
	}
	// A single healthy version scan yields no actionable remediations, which
	// the human renderer states explicitly.
	if !strings.Contains(out, "No actionable remediations") {
		t.Errorf("expected empty-recommendation notice, got:\n%s", out)
	}
}

// TestRecommendEmptyStore verifies the no-scans error path.
func TestRecommendEmptyStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	if _, err := execRecommend(t, dbPath, "--json=false", "--severity=", "--limit=25"); err == nil {
		t.Error("expected error when store has no scans")
	}
}
