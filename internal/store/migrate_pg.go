package store

import (
	"context"
	"database/sql"
)

// pgMigrations holds the Postgres-flavored DDL for each schema version.
// Versions are numerically aligned with the SQLite migrations in migrate.go
// so a database carries the same `schema_migrations` table contents whichever
// backend wrote it.
var pgMigrations = []migration{
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
    lat       DOUBLE PRECISION NOT NULL,
    lng       DOUBLE PRECISION NOT NULL,
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
    duration_ms  BIGINT,
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
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
`,
	},
}

// pgMigrationLockKey is the pg_advisory_xact_lock key that serializes schema
// migrations across replicas starting at the same time.
const pgMigrationLockKey = 0x666c656574 // "fleet"

// postgresDialect applies migrations to Postgres under a transaction-scoped
// advisory lock so replicas starting together never race on DDL.
var postgresDialect = dialect{
	Name:   "postgres",
	Rebind: rebind,
	Lock: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", pgMigrationLockKey)
		return err
	},
}

// migratePostgres brings a Postgres schema to the latest version.
func migratePostgres(ctx context.Context, db *sql.DB) error {
	return runMigrations(ctx, db, postgresDialect, pgMigrations)
}
