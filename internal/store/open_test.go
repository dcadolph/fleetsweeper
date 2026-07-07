package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestOpenSQLite verifies the sqlite driver (and the empty default) return a
// usable Store.
func TestOpenSQLite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name   string
		Driver string
	}{{ // Test 0: Explicit sqlite driver.
		Name: "explicit", Driver: "sqlite",
	}, { // Test 1: Empty driver defaults to sqlite.
		Name: "default", Driver: "",
	}, { // Test 2: Driver match is case-insensitive.
		Name: "uppercase", Driver: "SQLite",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "open.db")
			st, err := Open(test.Driver, path)
			if err != nil {
				t.Fatalf("test %d: open: %v", i, err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if _, err := st.ListScans(context.Background(), 1); err != nil {
				t.Errorf("test %d: store not usable: %v", i, err)
			}
		})
	}
}

// TestOpenUnknownDriver verifies an unrecognized driver name is rejected.
func TestOpenUnknownDriver(t *testing.T) {
	t.Parallel()
	if _, err := Open("mysql", "dsn"); !errors.Is(err, ErrStore) {
		t.Errorf("want ErrStore, got %v", err)
	}
}

// TestOpenPostgresBadDSN verifies the postgres branch is reachable and that an
// unreachable DSN surfaces as an error rather than a panic. This exercises the
// NewPostgres connection/ping failure path without a live database.
func TestOpenPostgresBadDSN(t *testing.T) {
	t.Parallel()
	// Port 1 refuses connections immediately, so the ping fails fast.
	if _, err := Open("postgres", "postgres://user:pass@127.0.0.1:1/db?sslmode=disable&connect_timeout=2"); err == nil {
		t.Error("expected an error connecting to an unreachable postgres DSN")
	}
}

// TestDetectDriver verifies DSN-prefix based driver inference.
func TestDetectDriver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		DSN  string
		Want Driver
	}{{ // Test 0: postgres:// URL selects Postgres.
		Name: "postgres", DSN: "postgres://u:p@h:5432/db", Want: DriverPostgres,
	}, { // Test 1: postgresql:// URL selects Postgres.
		Name: "postgresql", DSN: "postgresql://u:p@h/db", Want: DriverPostgres,
	}, { // Test 2: Filesystem path selects SQLite.
		Name: "path", DSN: "/var/lib/fleetsweeper.db", Want: DriverSQLite,
	}, { // Test 3: Empty DSN falls back to SQLite.
		Name: "empty", DSN: "", Want: DriverSQLite,
	}, { // Test 4: Bare filename selects SQLite.
		Name: "filename", DSN: "data.db", Want: DriverSQLite,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.Want, DetectDriver(test.DSN)); diff != "" {
				t.Errorf("test %d: (-want +got):\n%s", i, diff)
			}
		})
	}
}

// TestMigrateIdempotent verifies reopening the same database file re-runs
// migrate cleanly, skipping already-applied versions, and that prior data
// survives.
func TestMigrateIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reopen.db")

	first, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := first.SaveGroup(ctx, "prod", []string{"a"}); err != nil {
		t.Fatalf("save group: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	g, err := second.GetGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("get group after reopen: %v", err)
	}
	if diff := cmp.Diff([]string{"a"}, g.Clusters); diff != "" {
		t.Errorf("data lost across reopen (-want +got):\n%s", diff)
	}
}

// TestNewSQLiteBadPath verifies opening a database under a non-existent
// directory fails during migration rather than returning a broken store.
func TestNewSQLiteBadPath(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "does-not-exist", "nested", "x.db")
	if _, err := NewSQLite(path); err == nil {
		t.Error("expected an error opening under a non-existent directory")
	}
}
