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

	"github.com/dcadolph/fleetsweeper/internal/scanner"
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
// search_path points at it. Skips the test when envPostgresDSN is unset.
func testPGSchemaDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(envPostgresDSN)
	if dsn == "" {
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

// TestPostgresScanRoundTrip exercises the headline path: save a scan with
// per-cluster results, list it, fetch it, and reconstruct the result map.
func TestPostgresScanRoundTrip(t *testing.T) {
	t.Parallel()
	p := newTestPostgres(t)
	ctx := context.Background()

	results := map[string]map[string]scanner.Result{
		"prod-east": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.5"}}},
		"prod-west": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.0"}}},
	}
	scanID, err := p.SaveScan(ctx, []string{"prod-east", "prod-west"}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	list, err := p.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(list) != 1 || list[0].ID != scanID {
		t.Fatalf("unexpected scan list: %+v", list)
	}

	got, err := p.GetScanResults(ctx, scanID)
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	if got["prod-east"]["version"].Scanner != "version" {
		t.Errorf("missing east version data: %+v", got)
	}
}

// TestPostgresScanResultStateRoundTrip verifies State and Reason survive the
// Postgres backend the same way they survive SQLite.
func TestPostgresScanResultStateRoundTrip(t *testing.T) {
	t.Parallel()
	p := newTestPostgres(t)
	ctx := context.Background()

	want := map[string]scanner.Result{
		"version": {Scanner: "version", Data: map[string]any{"minor": float64(31)}},
		"certs":   {Scanner: "certs", State: scanner.StateErrored, Reason: "context deadline exceeded"},
		"workloads": {
			Scanner: "workloads", State: scanner.StateDegraded, Reason: "2 of 9 namespaces forbidden",
			Data: map[string]any{"pods": float64(14)},
		},
	}
	scanID, err := p.SaveScan(ctx, []string{"edge-1"}, map[string]map[string]scanner.Result{"edge-1": want})
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	got, err := p.GetScanResults(ctx, scanID)
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	if diff := cmp.Diff(want, got["edge-1"]); diff != "" {
		t.Errorf("results mismatch (-want +got):\n%s", diff)
	}
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

// TestPostgresGroupCRUD verifies group create/list/delete round-trips.
func TestPostgresGroupCRUD(t *testing.T) {
	t.Parallel()
	p := newTestPostgres(t)
	ctx := context.Background()

	if err := p.SaveGroup(ctx, "prod", []string{"a", "b"}); err != nil {
		t.Fatalf("save group: %v", err)
	}
	g, err := p.GetGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if len(g.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(g.Clusters))
	}
	if err := p.DeleteGroup(ctx, "prod"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := p.GetGroup(ctx, "prod"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestPostgresAPIKey verifies the API key lifecycle survives a Postgres
// round-trip including the unique constraint on token_hash.
func TestPostgresAPIKey(t *testing.T) {
	t.Parallel()
	p := newTestPostgres(t)
	ctx := context.Background()

	rec := APIKeyRecord{
		ID:           "pg_key_1",
		TokenHash:    "pg_hash_unique",
		Name:         "pg-test",
		Role:         RoleOperator,
		ClusterScope: []string{"group:prod", "prod-east"},
	}
	if err := p.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := p.GetAPIKeyByHash(ctx, rec.TokenHash)
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.Role != RoleOperator || len(got.ClusterScope) != 2 {
		t.Errorf("unexpected key: %+v", got)
	}

	dup := rec
	dup.ID = "pg_key_2"
	if err := p.SaveAPIKey(ctx, dup); err == nil {
		t.Error("expected duplicate-hash error")
	}

	if err := p.RevokeAPIKey(ctx, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rec2, _ := p.GetAPIKey(ctx, rec.ID)
	if rec2.RevokedAt.IsZero() {
		t.Error("expected RevokedAt set after revoke")
	}
}

// TestPostgresAuditFilters verifies audit-log filter composition works the
// same way as the SQLite backend.
func TestPostgresAuditFilters(t *testing.T) {
	t.Parallel()
	p := newTestPostgres(t)
	ctx := context.Background()

	now := time.Now().UTC()
	entries := []AuditEntry{
		{ActorID: "alpha", Method: "POST", Path: "/x", Status: 202, Timestamp: now.Add(-2 * time.Hour)},
		{ActorID: "beta", Method: "POST", Path: "/x", Status: 500, Timestamp: now.Add(-1 * time.Hour)},
		{ActorID: "alpha", Method: "DELETE", Path: "/y", Status: 403, Timestamp: now.Add(-30 * time.Minute)},
	}
	for _, e := range entries {
		if err := p.SaveAuditEntry(ctx, e); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	got, err := p.ListAuditEntries(ctx, AuditListOptions{MinStatus: 400})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("MinStatus=400: want 2 rows, got %d", len(got))
	}
	got, err = p.ListAuditEntries(ctx, AuditListOptions{ActorID: "alpha"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ActorID=alpha: want 2 rows, got %d", len(got))
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
