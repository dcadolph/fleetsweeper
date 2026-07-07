package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestResolveScheduleContexts verifies the explicit and all-contexts branches.
func TestResolveScheduleContexts(t *testing.T) {
	t.Parallel()

	// Explicit list passes through when all=false.
	got, err := resolveScheduleContexts("", []string{"a", "b"}, false)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if diff := cmp.Diff([]string{"a", "b"}, got); diff != "" {
		t.Errorf("explicit mismatch (-want +got):\n%s", diff)
	}

	// all=true reads the kubeconfig contexts.
	kubeconfig := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	names, err := resolveScheduleContexts(kubeconfig, nil, true)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if diff := cmp.Diff([]string{"alpha", "beta"}, names); diff != "" {
		t.Errorf("all-contexts mismatch (-want +got):\n%s", diff)
	}
}

// TestOpenServeStore verifies the demo in-memory fallback, the missing-db
// error, and opening a real path.
func TestOpenServeStore(t *testing.T) {
	// Demo mode with no --db falls back to an in-memory store.
	st, err := openServeStore(newStoreCmd(""), true)
	if err != nil {
		t.Fatalf("demo: %v", err)
	}
	if st == nil {
		t.Fatal("demo store is nil")
	}
	st.Close()

	// Non-demo with no --db is an error.
	if _, err := openServeStore(newStoreCmd(""), false); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("no-db non-demo: want ErrNoDatabase, got %v", err)
	}

	// A real path opens successfully.
	dbPath := filepath.Join(t.TempDir(), "serve.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("seed: %v", err)
	} else {
		s.Close()
	}
	real, err := openServeStore(newStoreCmd(dbPath), false)
	if err != nil {
		t.Fatalf("real path: %v", err)
	}
	real.Close()
}
