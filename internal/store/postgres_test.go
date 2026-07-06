package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// envPostgresDSN is the environment variable that points at a writable
// Postgres database for tests. When unset, every Postgres test in this file
// is skipped so the suite stays runnable offline.
const envPostgresDSN = "FLEETSWEEPER_PG_TEST_DSN"

// newTestPostgres opens a Postgres-backed Store against the DSN in the
// envPostgresDSN environment variable. Returns the backend and a cleanup
// function that drops every Fleetsweeper-managed table so the next test
// starts from a clean slate.
func newTestPostgres(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv(envPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a writable Postgres DSN to run", envPostgresDSN)
	}
	p, err := NewPostgres(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Drop in reverse-dependency order so foreign keys are satisfied.
		for _, tbl := range []string{
			"audit_log", "api_keys", "finding_acks",
			"cluster_locations", "group_clusters", "groups",
			"scan_results", "scans", "clusters",
			"schema_migrations",
		} {
			_, _ = p.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+tbl+" CASCADE")
		}
		_ = p.Close()
	})
	return p
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
