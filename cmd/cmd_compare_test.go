package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// execCompare executes the compare subcommand and captures its output, which
// compare writes through cmd.OutOrStdout().
func execCompare(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"compare"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestCompareFormats verifies text, json, and markdown rendering all run.
func TestCompareFormats(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cmp.db")
	ids := seedHistoryScans(t, dbPath, 2)

	for _, format := range []string{"text", "json", "markdown"} {
		out, err := execCompare(t, dbPath, ids[0], ids[1], "--format="+format, "--no-color=true")
		if err != nil {
			t.Fatalf("compare %s: %v\n%s", format, err, out)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("compare %s produced no output", format)
		}
	}
}

// TestCompareRequiresDB verifies the missing-db path surfaces an error.
func TestCompareRequiresDB(t *testing.T) {
	if _, err := execCompare(t, "", "a", "b", "--format=text"); err == nil {
		t.Error("expected error without --db")
	}
}
