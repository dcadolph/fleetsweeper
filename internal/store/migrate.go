package store

import (
	"database/sql"
	"fmt"
	"time"
)

// migration is one numbered, idempotent schema change applied at startup.
// Migrations execute in version order inside a single transaction and are
// recorded in the schema_migrations table so they run exactly once.
type migration struct {
	// Version is the monotonic migration identifier.
	Version int
	// SQL is the migration body. Multiple statements are allowed.
	SQL string
}

// migrations is the ordered list of schema changes. Append new versions to the
// end; never edit existing entries once they have shipped.
var migrations = []migration{
	{
		Version: 1,
		SQL: `
CREATE TABLE IF NOT EXISTS scans (
    id        TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    clusters  TEXT NOT NULL,
    scanners  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id   TEXT NOT NULL,
    cluster   TEXT NOT NULL,
    scanner   TEXT NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, cluster, scanner),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS clusters (
    name       TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS group_clusters (
    group_name   TEXT NOT NULL,
    cluster_name TEXT NOT NULL,
    PRIMARY KEY (group_name, cluster_name),
    FOREIGN KEY (group_name) REFERENCES groups(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_results_cluster ON scan_results(cluster);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
`,
	},
	{
		Version: 2,
		SQL: `
CREATE INDEX IF NOT EXISTS idx_scan_results_cluster_scan ON scan_results(cluster, scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp_desc ON scans(timestamp DESC);
`,
	},
	{
		Version: 3,
		SQL: `
CREATE TABLE IF NOT EXISTS cluster_locations (
    cluster   TEXT PRIMARY KEY,
    lat       REAL NOT NULL,
    lng       REAL NOT NULL,
    site      TEXT,
    notes     TEXT,
    updated_at TEXT NOT NULL
);
`,
	},
}

// migrate ensures the schema is at the latest version. It is safe to call
// repeatedly; already-applied versions are skipped.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("%w: bootstrap migrations table: %w", ErrMigrate, err)
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("%w: begin migration %d: %w", ErrMigrate, m.Version, err)
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%w: run migration %d: %w", ErrMigrate, m.Version, err)
		}
		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
			m.Version, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%w: record migration %d: %w", ErrMigrate, m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: commit migration %d: %w", ErrMigrate, m.Version, err)
		}
	}
	return nil
}

// appliedVersions returns the set of migration versions already recorded.
func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("%w: list migrations: %w", ErrMigrate, err)
	}
	defer rows.Close()
	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("%w: scan migration row: %w", ErrMigrate, err)
		}
		out[v] = true
	}
	return out, rows.Err()
}
