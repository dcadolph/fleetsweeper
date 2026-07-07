package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestCleanScope verifies trimming, de-duplication, and the wildcard default.
func TestCleanScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantScope []string
		In        []string
	}{
		{WantScope: []string{store.ScopeWildcard}, In: nil},                 // Test 0: Empty defaults to wildcard.
		{WantScope: []string{store.ScopeWildcard}, In: []string{" ", ""}},   // Test 1: Blanks collapse to wildcard.
		{WantScope: []string{"a", "b"}, In: []string{"a", "b", "a", " b "}}, // Test 2: Trim and dedupe.
	}
	for testNum, test := range tests {
		t.Run("case", func(t *testing.T) {
			t.Parallel()
			got := cleanScope(test.In)
			if diff := cmp.Diff(test.WantScope, got); diff != "" {
				t.Errorf("test %d: mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestWriteAPIKeyJSON verifies compact and pretty JSON emission.
func TestWriteAPIKeyJSON(t *testing.T) {
	t.Parallel()

	compact := &bytes.Buffer{}
	cmd := newBufferedCmd(compact)
	if err := writeAPIKeyJSON(cmd, map[string]string{"k": "v"}, false); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if strings.Contains(compact.String(), "\n  ") {
		t.Errorf("compact output should not be indented: %q", compact.String())
	}

	pretty := &bytes.Buffer{}
	cmd2 := newBufferedCmd(pretty)
	if err := writeAPIKeyJSON(cmd2, map[string]string{"k": "v"}, true); err != nil {
		t.Fatalf("pretty: %v", err)
	}
	if !strings.Contains(pretty.String(), "\n  ") {
		t.Errorf("pretty output should be indented: %q", pretty.String())
	}
}

// runAPIKey executes the apikey subcommand against a temp DB.
func runAPIKey(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"apikey"}, args...)
	// Always pass --db explicitly so a leaked value from a prior Execute on
	// the shared rootCmd cannot mask the empty-path case.
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestAPIKeyCreateListRevoke walks a full lifecycle against a temp store.
func TestAPIKeyCreateListRevoke(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keys.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}

	out, err := runAPIKey(t, dbPath, "create", "--name=ci-runner", "--role=operator", "--scope=*")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode create: %v\n%s", err, out)
	}
	if created.ID == "" || created.Token == "" {
		t.Fatalf("create output missing id/token: %s", out)
	}

	list, err := runAPIKey(t, dbPath, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, list)
	}
	if !strings.Contains(list, created.ID) {
		t.Errorf("list missing created id:\n%s", list)
	}
	// The raw token must never surface in the list output.
	if strings.Contains(list, created.Token) {
		t.Errorf("raw token leaked into list output")
	}

	if _, err := runAPIKey(t, dbPath, "revoke", created.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	s, _ := store.NewSQLite(dbPath)
	defer s.Close()
	rec, err := s.GetAPIKey(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get after revoke: %v", err)
	}
	if rec.RevokedAt.IsZero() {
		t.Error("expected RevokedAt to be set after revoke")
	}
}

// TestAPIKeyCreateValidation verifies the required-name and role checks.
func TestAPIKeyCreateValidation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keys.db")
	if s, err := store.NewSQLite(dbPath); err == nil {
		s.Close()
	}
	// Pass --name explicitly empty to override any value the shared rootCmd
	// retained from a prior create; runAPIKeyCreate rejects an empty name.
	if _, err := runAPIKey(t, dbPath, "create", "--name="); err == nil {
		t.Error("expected error when --name is empty")
	}
	if _, err := runAPIKey(t, dbPath, "create", "--name=x", "--role=wizard"); err == nil {
		t.Error("expected error for invalid role")
	}
}

// TestAPIKeyRequiresDB verifies list without --db returns the sentinel.
func TestAPIKeyRequiresDB(t *testing.T) {
	if _, err := runAPIKey(t, "", "list"); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("want ErrNoDatabase, got %v", err)
	}
}
