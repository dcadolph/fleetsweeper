package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestMigrationVersionsAligned verifies both migration lists carry the same
// versions and that each list counts up from 1 without gaps.
func TestMigrationVersionsAligned(t *testing.T) {
	t.Parallel()

	versions := func(ms []migration) []int {
		out := make([]int, 0, len(ms))
		for _, m := range ms {
			out = append(out, m.Version)
		}
		return out
	}

	tests := []struct {
		Name        string
		In          []migration
		WantVersion []int
	}{{ // Test 0: SQLite versions are sequential from 1.
		Name: "sqlite", In: migrations, WantVersion: sequence(len(migrations)),
	}, { // Test 1: Postgres versions are sequential from 1.
		Name: "postgres", In: pgMigrations, WantVersion: sequence(len(pgMigrations)),
	}, { // Test 2: Both lists carry the same versions.
		Name: "aligned", In: pgMigrations, WantVersion: versions(migrations),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := versions(test.In)
			if diff := cmp.Diff(test.WantVersion, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("versions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// sequence returns 1 through n.
func sequence(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i + 1
	}
	return out
}

// TestMigrationSchemaParity verifies SQLite and Postgres end up with the same
// tables and column names after all migrations run.
func TestMigrationSchemaParity(t *testing.T) {
	t.Parallel()
	pg := newTestPostgres(t)
	sq := newTestSQLite(t)
	ctx := context.Background()

	sqliteCols, err := sqliteColumns(ctx, sq.db)
	if err != nil {
		t.Fatalf("sqlite columns: %v", err)
	}
	pgCols, err := postgresColumns(ctx, pg.db)
	if err != nil {
		t.Fatalf("postgres columns: %v", err)
	}
	if diff := cmp.Diff(sqliteCols, pgCols, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("schema mismatch (-sqlite +postgres):\n%s", diff)
	}
}

// sqliteColumns maps each user table to its sorted column names.
func sqliteColumns(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !strings.HasPrefix(name, "sqlite_") {
			tables = append(tables, name)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make(map[string][]string, len(tables))
	for _, table := range tables {
		info, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%q)", table))
		if err != nil {
			return nil, err
		}
		for info.Next() {
			var (
				cid, notNull, pk int
				name, typ        string
				dflt             sql.NullString
			)
			if err := info.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				_ = info.Close()
				return nil, err
			}
			out[table] = append(out[table], name)
		}
		if err := info.Close(); err != nil {
			return nil, err
		}
		if err := info.Err(); err != nil {
			return nil, err
		}
		sort.Strings(out[table])
	}
	return out, nil
}

// postgresColumns maps each table in the current schema to its sorted column names.
func postgresColumns(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT table_name, column_name
		FROM information_schema.columns WHERE table_schema = current_schema()`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			return nil, err
		}
		out[table] = append(out[table], col)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, cols := range out {
		sort.Strings(cols)
	}
	return out, nil
}
