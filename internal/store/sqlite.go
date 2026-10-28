package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// SQLite implements Store using a SQLite database.
type SQLite struct {
	// sqlStore holds the queries SQLite shares with Postgres.
	sqlStore
}

// NewSQLite opens or creates a SQLite database at path and runs migrations.
// WAL is enabled for read/write concurrency; busy_timeout retries instead of
// failing under contention; foreign_keys are required for ON DELETE CASCADE
// to work on scan_results.
func NewSQLite(path string) (*SQLite, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", ErrStore, err)
	}
	// An in-memory database lives inside a single connection: a pool would give
	// each connection its own empty database, so migrations applied on one would
	// be missing on the others and queries would fail with "no such table". Pin
	// the pool to one connection so the schema and data are visible everywhere.
	if isMemoryDSN(path) {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	} else {
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(2)
	}
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLite{sqlStore{db: db, d: sqliteDialect}}, nil
}

// isMemoryDSN reports whether path opens an in-memory SQLite database, which is
// private to the connection that created it.
func isMemoryDSN(path string) bool {
	return path == ":memory:" || strings.Contains(path, ":memory:") || strings.Contains(path, "mode=memory")
}

// Vacuum reclaims free pages by running SQLite VACUUM.
func (s *SQLite) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "VACUUM")
	if err != nil {
		return fmt.Errorf("%w: vacuum: %w", ErrStore, err)
	}
	return nil
}

// VacuumInto writes a consistent snapshot of the database to the given file
// path. Wraps the SQLite `VACUUM INTO` statement which captures the entire
// database state atomically without blocking concurrent reads. The target
// path must not already exist.
func (s *SQLite) VacuumInto(ctx context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("%w: vacuum into: empty path", ErrStore)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return fmt.Errorf("%w: vacuum into: %w", ErrStore, err)
	}
	return nil
}
