package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/remediate"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestParseRepoSpec verifies owner/repo splitting and the malformed cases.
func TestParseRepoSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In        string
		WantOwner string
		WantRepo  string
		WantErr   bool
	}{
		{In: "octo/hello", WantOwner: "octo", WantRepo: "hello"}, // Test 0: Well-formed spec.
		{In: "noslash", WantErr: true},                           // Test 1: Missing separator.
		{In: "/repo", WantErr: true},                             // Test 2: Empty owner.
		{In: "owner/", WantErr: true},                            // Test 3: Empty repo.
		{In: "", WantErr: true},                                  // Test 4: Empty string.
	}
	for testNum, test := range tests {
		t.Run(test.In, func(t *testing.T) {
			t.Parallel()
			owner, repo, err := parseRepoSpec(test.In)
			if test.WantErr {
				if err == nil {
					t.Fatalf("test %d: want error, got nil", testNum)
				}
				return
			}
			if err != nil {
				t.Fatalf("test %d: unexpected error: %v", testNum, err)
			}
			if owner != test.WantOwner || repo != test.WantRepo {
				t.Errorf("test %d: got (%q, %q), want (%q, %q)", testNum, owner, repo, test.WantOwner, test.WantRepo)
			}
		})
	}
}

// TestFilterRemediable verifies scoping to a cluster (or fleet), the scanner
// filter, and exclusion of findings lacking inline YAML.
func TestFilterRemediable(t *testing.T) {
	t.Parallel()
	withYAML := &report.Remediation{YAML: "kind: NetworkPolicy"}
	findings := []report.Finding{
		{Title: "match", Cluster: "prod", Scanner: "networkpolicy", Remediation: withYAML},
		{Title: "fleet", Cluster: "fleet", Scanner: "networkpolicy", Remediation: withYAML},
		{Title: "other-cluster", Cluster: "dev", Scanner: "networkpolicy", Remediation: withYAML},
		{Title: "no-yaml", Cluster: "prod", Scanner: "networkpolicy", Remediation: &report.Remediation{Command: "kubectl"}},
		{Title: "wrong-scanner", Cluster: "prod", Scanner: "rbac", Remediation: withYAML},
	}

	// Test 0: No scanner filter keeps every prod/fleet finding that ships
	// YAML; the other-cluster and no-yaml rows drop out.
	got := filterRemediable(findings, "prod", "")
	titles := findingTitles(got)
	if diff := cmp.Diff([]string{"match", "fleet", "wrong-scanner"}, titles, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("unfiltered mismatch (-want +got):\n%s", diff)
	}

	// Test 1: Scanner filter narrows to the networkpolicy finding only.
	got = filterRemediable(findings, "prod", "rbac")
	if diff := cmp.Diff([]string{"wrong-scanner"}, findingTitles(got), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("scanner filter mismatch (-want +got):\n%s", diff)
	}
}

// findingTitles pulls the Title field off each finding for order assertions.
func findingTitles(fs []report.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

// TestPrintResultDryRun verifies the dry-run rendering includes the planned
// YAML and the no-push notice.
func TestPrintResultDryRun(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	cmd := newBufferedCmd(buf)
	printResult(cmd, remediate.Result{
		DryRun:      true,
		HeadBranch:  "fix/np",
		BaseBranch:  "main",
		TargetPath:  "fleetsweeper/prod/np.yaml",
		PRTitle:     "Add default-deny",
		PlannedYAML: "kind: NetworkPolicy",
	})
	out := buf.String()
	for _, want := range []string{"dry run", "fix/np", "planned YAML", "kind: NetworkPolicy"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, out)
		}
	}
}

// TestPrintResultPushed verifies the pushed rendering shows the PR URL/number.
func TestPrintResultPushed(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	cmd := newBufferedCmd(buf)
	printResult(cmd, remediate.Result{
		PRURL:    "https://github.com/o/r/pull/7",
		PRNumber: 7,
		PRTitle:  "Add default-deny",
	})
	out := buf.String()
	if !strings.Contains(out, "PR opened") || !strings.Contains(out, "#7") {
		t.Errorf("pushed output missing PR details:\n%s", out)
	}
}

// execRemediate runs the remediate subcommand against a temp DB.
func execRemediate(t *testing.T, dbPath string, args ...string) error {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"remediate"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	return rootCmd.Execute()
}

// TestRemediateBadRepo verifies an invalid --github-repo is rejected before
// any store access.
func TestRemediateBadRepo(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rem.db")
	if s, err := store.NewSQLite(dbPath); err == nil {
		s.Close()
	}
	err := execRemediate(t, dbPath,
		"--scan-id=latest", "--cluster=prod", "--github-repo=noslash", "--push=false")
	if err == nil {
		t.Error("expected error for malformed --github-repo")
	}
}

// TestRemediateNoScans verifies pickFinding surfaces the empty-store error via
// the 'latest' alias.
func TestRemediateNoScans(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rem.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	err := execRemediate(t, dbPath,
		"--scan-id=latest", "--cluster=prod", "--github-repo=octo/repo", "--push=false")
	if err == nil {
		t.Error("expected error when store has no scans")
	}
}
