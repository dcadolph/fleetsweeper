package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// execWhatif runs the whatif subcommand against dbPath. Every flag is reset
// first because rootCmd keeps flag values across Execute calls.
func execWhatif(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := []string{
		"whatif", "--db=" + dbPath, "--cluster=", "--field=", "--fix=", "--scope=fleet", "--scan-id=latest", "--json=false",
	}
	rootCmd.SetArgs(append(full, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestWhatifCommand verifies the command projects a fix on the latest stored
// scan in JSON and text, and rejects incomplete or inapplicable requests.
func TestWhatifCommand(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "whatif.db")
	seedStepScans(t, dbPath)

	out, err := execWhatif(t, dbPath, "--cluster=c04", "--field=security/enforced_count", "--json=true")
	if err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	var got report.Outcome
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if got.Fix.Kind != report.FixMedian || got.ScoreAfter <= got.ScoreBefore {
		t.Errorf("want a median fix that raises the score, got kind %q score %d -> %d", got.Fix.Kind, got.ScoreBefore,
			got.ScoreAfter)
	}
	if diff := cmp.Diff([]string{"c04"}, got.ClearedOutliers, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("cleared mismatch (-want +got):\n%s", diff)
	}

	text, err := execWhatif(t, dbPath, "--cluster=c04", "--field=security/enforced_count", "--scan-id=scan-6")
	if err != nil {
		t.Fatalf("text: %v\n%s", err, text)
	}
	for _, want := range []string{
		"What if c04 security/enforced_count were fixed (median, fleet norm)?",
		fmt.Sprintf("Fleet score: %d -> %d", got.ScoreBefore, got.ScoreAfter),
		"No longer flagged: c04",
		"Nothing was changed.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}

	for _, args := range [][]string{
		{"--cluster=c04"},
		{"--cluster=c04", "--field=enforced_count"},
		{"--cluster=c04", "--field=security/nope"},
		{"--cluster=c04", "--field=security/enforced_count", "--fix=mode"},
		{"--cluster=c04", "--field=security/enforced_count", "--scan-id=missing"},
	} {
		if _, err := execWhatif(t, dbPath, args...); err == nil {
			t.Errorf("args %v: want an error", args)
		}
	}
}
