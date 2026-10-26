package store

import (
	"context"
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
	{
		Version: 4,
		SQL: `
CREATE TABLE IF NOT EXISTS finding_acks (
    fingerprint   TEXT PRIMARY KEY,
    cluster       TEXT,
    scanner       TEXT,
    title         TEXT,
    ack_by        TEXT,
    reason        TEXT,
    snooze_until  TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_acks_snooze ON finding_acks(snooze_until);
`,
	},
	{
		Version: 5,
		SQL: `
CREATE TABLE IF NOT EXISTS api_keys (
    id            TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL,
    cluster_scope TEXT NOT NULL DEFAULT '["*"]',
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT,
    revoked_at    TEXT,
    created_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash ON api_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id           TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    actor_id     TEXT,
    actor_name   TEXT,
    actor_role   TEXT,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    status       INTEGER NOT NULL,
    remote_addr  TEXT,
    user_agent   TEXT,
    duration_ms  INTEGER,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
`,
	},
	{
		Version: 6,
		SQL: `
CREATE TABLE IF NOT EXISTS alerts (
    fingerprint   TEXT PRIMARY KEY,
    cluster       TEXT NOT NULL,
    status        TEXT NOT NULL,
    alertname     TEXT NOT NULL,
    severity      TEXT,
    summary       TEXT,
    starts_at     TEXT,
    ends_at       TEXT,
    received_at   TEXT NOT NULL,
    labels_json   TEXT NOT NULL,
    annotations_json TEXT NOT NULL,
    generator_url TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_cluster ON alerts(cluster);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC);
`,
	},
	{
		Version: 7,
		SQL: `
CREATE TABLE IF NOT EXISTS cluster_tags (
    cluster    TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (cluster, key)
);
CREATE INDEX IF NOT EXISTS idx_cluster_tags_key_value ON cluster_tags(key, value);
`,
	},
	{
		Version: 8,
		SQL: `
ALTER TABLE scan_results ADD COLUMN state TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_results ADD COLUMN reason TEXT NOT NULL DEFAULT '';
`,
	},
}

// dialect holds what differs between the backends when applying migrations.
type dialect struct {
	// Name labels the backend in error messages.
	Name string
	// Rebind converts the runner's ? placeholders to the backend's style.
	Rebind func(q string) string
	// Lock serializes migrations across processes inside tx. Nil when the
	// backend needs no cross-process lock.
	Lock func(ctx context.Context, tx *sql.Tx) error
}

// sqliteDialect applies migrations to SQLite, which takes its write lock per
// transaction and needs no extra serialization.
var sqliteDialect = dialect{Name: "sqlite", Rebind: func(q string) string { return q }}

// migrate brings a SQLite schema to the latest version.
func migrate(ctx context.Context, db *sql.DB) error {
	return runMigrations(ctx, db, sqliteDialect, migrations)
}

// runMigrations brings the schema to the latest version in ms. It is safe to
// call repeatedly and from several processes at once: each migration runs in
// its own transaction, holds the dialect's lock when it has one, and rechecks
// schema_migrations after taking it, so every version applies exactly once.
func runMigrations(ctx context.Context, db *sql.DB, d dialect, ms []migration) error {
	if err := inMigrationTx(ctx, db, d, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
		return err
	}); err != nil {
		return fmt.Errorf("%w: %s: bootstrap migrations table: %w", ErrMigrate, d.Name, err)
	}

	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if applied[m.Version] {
			continue
		}
		if err := inMigrationTx(ctx, db, d, func(tx *sql.Tx) error { return applyMigration(ctx, tx, d, m) }); err != nil {
			return fmt.Errorf("%w: %s: migration %d: %w", ErrMigrate, d.Name, m.Version, err)
		}
	}
	return nil
}

// inMigrationTx runs fn in a transaction holding the dialect's lock and
// commits it when fn succeeds.
func inMigrationTx(ctx context.Context, db *sql.DB, d dialect, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after Commit is a no-op.
	if d.Lock != nil {
		if err := d.Lock(ctx, tx); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// applyMigration runs m and records it unless another process recorded it
// while this one waited for the lock.
func applyMigration(ctx context.Context, tx *sql.Tx, d dialect, m migration) error {
	var done bool
	if err := tx.QueryRowContext(ctx,
		d.Rebind("SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = ?)"), m.Version,
	).Scan(&done); err != nil {
		return fmt.Errorf("check applied: %w", err)
	}
	if done {
		return nil
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		d.Rebind("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"),
		m.Version, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	return nil
}

// appliedVersions returns the set of migration versions already recorded.
func appliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
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
