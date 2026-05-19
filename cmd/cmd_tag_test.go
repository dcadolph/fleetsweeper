package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// runTag executes the tag subcommand against a temp DB and returns
// captured output.
func runTag(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"tag"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestTagSetThenList verifies a set + list round-trip emits the tags.
func TestTagSetThenList(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tags.db")
	// Seed the DB so migrations run.
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.Close()

	if _, err := runTag(t, dbPath, "set", "prod-east", "env=prod", "tier=critical"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := runTag(t, dbPath, "set", "dev-1", "env=staging"); err != nil {
		t.Fatalf("set: %v", err)
	}

	out, err := runTag(t, dbPath, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "prod-east") || !strings.Contains(out, "env=prod") ||
		!strings.Contains(out, "tier=critical") || !strings.Contains(out, "dev-1") {
		t.Errorf("missing rows in list output:\n%s", out)
	}
}

// TestTagDel removes one key and confirms it disappears from the store.
func TestTagDel(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tags2.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	_ = s.SetClusterTag(ctx, "prod-east", "env", "prod")
	_ = s.SetClusterTag(ctx, "prod-east", "tier", "critical")
	s.Close()

	if _, err := runTag(t, dbPath, "del", "prod-east", "tier"); err != nil {
		t.Fatalf("del: %v", err)
	}

	// Reopen to verify (the CLI closed it after deletion).
	s, _ = store.NewSQLite(dbPath)
	defer s.Close()
	got, _ := s.GetClusterTags(ctx, "prod-east")
	if _, ok := got["tier"]; ok {
		t.Errorf("tier should be gone, got %+v", got)
	}
	if got["env"] != "prod" {
		t.Errorf("env should remain, got %+v", got)
	}
}

// TestTagSet_RejectsMalformedPair verifies the CLI returns a non-nil
// error when a pair lacks an "=".
func TestTagSet_RejectsMalformedPair(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tags3.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	if _, err := runTag(t, dbPath, "set", "prod-east", "bogus"); err == nil {
		t.Error("expected error for malformed pair")
	}
}
