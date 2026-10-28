package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Postgres implements Store against a PostgreSQL database. It is functionally
// equivalent to SQLite but tolerates concurrent writers, so multi-replica
// fleetsweeper deployments share a single backend. Timestamps are stored as
// RFC3339 TEXT and JSON columns as TEXT so the same row marshaling code as
// SQLite continues to work; the performance cost is negligible at the row
// volumes Fleetsweeper produces.
type Postgres struct {
	// sqlStore holds the queries Postgres shares with SQLite.
	sqlStore
}

// NewPostgres opens a connection pool against the given DSN and applies
// migrations. The DSN is a standard libpq/pgx URL such as
// "postgres://user:pass@host:5432/db?sslmode=require".
func NewPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", ErrStore, err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %w", ErrStore, err)
	}

	if err := migratePostgres(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Postgres{sqlStore{db: db, d: postgresDialect}}, nil
}

// rebind converts the SQLite-style `?` placeholders used throughout this
// package into the PostgreSQL-style `$1, $2, ...` form. Both backends share
// the same query strings via this single translation point.
func rebind(query string) string {
	if !strings.ContainsRune(query, '?') {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Vacuum is a no-op on Postgres because autovacuum runs in the background.
// The method exists so the Store interface stays uniform.
func (p *Postgres) Vacuum(_ context.Context) error {
	return nil
}
