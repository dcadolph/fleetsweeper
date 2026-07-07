package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// newGroupCmd returns a store-bound command with the group --clusters flag.
func newGroupCmd(dbPath string, clusters ...string) *cobra.Command {
	cmd := newStoreCmd(dbPath)
	cmd.Flags().StringSlice("clusters", clusters, "")
	return cmd
}

// TestGroupLifecycle exercises create, add, remove, and delete against a store.
func TestGroupLifecycle(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "groups.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	ctx := context.Background()

	// Create with two clusters.
	if err := runGroupCreate(newGroupCmd(dbPath, "a", "b"), []string{"prod"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := groupMembers(t, dbPath, "prod"); len(got) != 2 {
		t.Fatalf("after create: want 2 members, got %v", got)
	}

	// List runs without error.
	if err := runGroupList(newGroupCmd(dbPath), nil); err != nil {
		t.Fatalf("list: %v", err)
	}

	// Add a third cluster.
	if err := runGroupAddCluster(newGroupCmd(dbPath, "c"), []string{"prod"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := groupMembers(t, dbPath, "prod"); len(got) != 3 {
		t.Errorf("after add: want 3 members, got %v", got)
	}

	// Remove one cluster.
	if err := runGroupRemoveCluster(newGroupCmd(dbPath, "a"), []string{"prod"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := groupMembers(t, dbPath, "prod"); len(got) != 2 {
		t.Errorf("after remove: want 2 members, got %v", got)
	}

	// Delete the group.
	if err := runGroupDelete(newGroupCmd(dbPath), []string{"prod"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	s, _ := store.NewSQLite(dbPath)
	defer s.Close()
	if _, err := s.GetGroup(ctx, "prod"); err == nil {
		t.Error("expected error fetching deleted group")
	}
}

// TestGroupRequiresDB verifies the missing-db sentinel from a group run.
func TestGroupRequiresDB(t *testing.T) {
	t.Parallel()
	if err := runGroupList(newGroupCmd(""), nil); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("want ErrNoDatabase, got %v", err)
	}
}

// groupMembers reopens the store and returns the named group's cluster list.
func groupMembers(t *testing.T, dbPath, name string) []string {
	t.Helper()
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	g, err := s.GetGroup(context.Background(), name)
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	return g.Clusters
}
