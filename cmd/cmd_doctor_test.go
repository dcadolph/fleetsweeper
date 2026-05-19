package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestDoctorJSONReport verifies the doctor command emits structured JSON
// when --json is set, and that a missing kubeconfig produces a Fail
// rather than a Skip (the harness has no real cluster).
//
// Doctor tests share the package-level rootCmd, which cobra parses
// mutably. They run sequentially to avoid flag-state races.
func TestDoctorJSONReport(t *testing.T) {
	db := filepath.Join(t.TempDir(), "doctor.db")
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"doctor",
		"--db=" + db,
		"--kubeconfig=" + filepath.Join(t.TempDir(), "absent-config"),
		"--json",
	})
	_ = rootCmd.Execute()

	body := buf.String()
	if !strings.Contains(body, `"summary"`) {
		t.Fatalf("JSON output missing summary: %s", body)
	}
	var rep Report
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if len(rep.Checks) == 0 {
		t.Error("no checks in report")
	}
	dbCheck := findCheck(rep, "database")
	if dbCheck.Status != StatusOK {
		t.Errorf("database: want ok, got %s (%s)", dbCheck.Status, dbCheck.Detail)
	}
	kubeCheck := findCheck(rep, "kubeconfig")
	if kubeCheck.Status != StatusFail {
		t.Errorf("kubeconfig: want fail for missing file, got %s", kubeCheck.Status)
	}
}

// TestDoctorHumanOutput verifies the default text mode renders a table.
func TestDoctorHumanOutput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "doctor.db")
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"doctor", "--db=" + db, "--kubeconfig=", "--json=false"})
	_ = rootCmd.Execute()
	body := buf.String()
	for _, want := range []string{"status", "check", "summary:"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in output:\n%s", want, body)
		}
	}
}

// findCheck returns the result for the named check, or a zero-value
// CheckResult when none matched.
func findCheck(r Report, name string) CheckResult {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return CheckResult{}
}
