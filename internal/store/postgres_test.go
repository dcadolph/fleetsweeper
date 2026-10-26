package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// envPostgresDSN is the environment variable that points at a writable
// Postgres database for tests. When unset, every Postgres test in this file
// is skipped so the suite stays runnable offline.
const envPostgresDSN = "FLEETSWEEPER_PG_TEST_DSN"

// newTestPostgres opens a Postgres-backed Store in a fresh schema of the
// database named by the envPostgresDSN environment variable, so parallel tests
// never see or drop each other's tables. The schema is dropped on cleanup.
func newTestPostgres(t *testing.T) *Postgres {
	t.Helper()
	return newTestPostgresAt(t, testPGSchemaDSN(t))
}

// newTestPostgresAt opens a Postgres-backed Store at dsn and closes it on
// cleanup.
func newTestPostgresAt(t *testing.T, dsn string) *Postgres {
	t.Helper()
	p, err := NewPostgres(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// testPGSchemaDSN creates an empty schema for one test and returns a DSN whose
// search_path points at it. Skips the test when envPostgresDSN is unset, and
// fails it instead under CI so the Postgres backend cannot go silently untested.
func testPGSchemaDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(envPostgresDSN)
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatalf("%s is unset in CI, so the Postgres backend would go untested", envPostgresDSN)
		}
		t.Skipf("set %s to a writable Postgres DSN to run", envPostgresDSN)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	schema := "fs_test_" + strings.ReplaceAll(generateID(), "-", "_")
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}

// TestPostgresConcurrentMigrate verifies several replicas opening an empty
// database at once all succeed and apply each migration exactly once. It runs
// in a private schema so the other tests' tables do not hide the race.
func TestPostgresConcurrentMigrate(t *testing.T) {
	t.Parallel()
	scoped := testPGSchemaDSN(t)

	const replicas = 8
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := NewPostgres(scoped)
			if err != nil {
				errs[i] = err
				return
			}
			errs[i] = p.Close()
		}(i)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent open: %v", err)
	}

	p := newTestPostgresAt(t, scoped)
	var applied int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if diff := cmp.Diff(len(pgMigrations), applied); diff != "" {
		t.Errorf("applied migrations mismatch (-want +got):\n%s", diff)
	}
}

// TestRebindParameters verifies that the `?` to `$N` translation is correct
// for arbitrary numbers of placeholders, including queries without any.
func TestRebindParameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		In      string
		WantOut string
	}{{
		Name: "Test 0: No placeholders is identity.", In: "SELECT 1", WantOut: "SELECT 1",
	}, {
		Name: "Test 1: Single placeholder becomes $1.", In: "SELECT * FROM t WHERE id = ?", WantOut: "SELECT * FROM t WHERE id = $1",
	}, {
		Name: "Test 2: Multiple placeholders count up.", In: "INSERT INTO t VALUES (?, ?, ?)", WantOut: "INSERT INTO t VALUES ($1, $2, $3)",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := rebind(test.In); got != test.WantOut {
				t.Errorf("test %d: want %q, got %q", i, test.WantOut, got)
			}
		})
	}
}
