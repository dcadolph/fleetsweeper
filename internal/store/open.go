package store

import (
	"fmt"
	"strings"
)

// Driver identifies a supported backend.
type Driver string

const (
	// DriverSQLite stores data in a single SQLite file. Default for single-instance
	// deployments. Concurrent readers are fine; writers are serialised by the
	// SQLite engine.
	DriverSQLite Driver = "sqlite"
	// DriverPostgres stores data in a PostgreSQL database. Use this when running
	// multiple fleetsweeper replicas behind a load balancer.
	DriverPostgres Driver = "postgres"
)

// Open returns a Store backed by the named driver. Recognised drivers are
// "sqlite" and "postgres"; the DSN format depends on the driver:
//   - sqlite: a filesystem path (":memory:" for ephemeral storage).
//   - postgres: a libpq/pgx URL, e.g. "postgres://user:pass@host:5432/db?sslmode=require".
func Open(driver, dsn string) (Store, error) {
	switch Driver(strings.ToLower(driver)) {
	case "", DriverSQLite:
		return NewSQLite(dsn)
	case DriverPostgres:
		return NewPostgres(dsn)
	default:
		return nil, fmt.Errorf("%w: unknown driver %q (expected sqlite or postgres)", ErrStore, driver)
	}
}

// DetectDriver infers the driver from a DSN's prefix. URL-shaped DSNs like
// "postgres://..." or "postgresql://..." choose Postgres; everything else
// falls back to SQLite. Callers can override with --db-driver when the DSN
// is ambiguous.
func DetectDriver(dsn string) Driver {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return DriverPostgres
	default:
		return DriverSQLite
	}
}
