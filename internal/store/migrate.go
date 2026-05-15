package store

import (
	"database/sql"
	"fmt"
)

// schema is the DDL for the fleetsweeper database.
const schema = `
CREATE TABLE IF NOT EXISTS scans (
    id        TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    clusters  TEXT NOT NULL,
    scanners  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id  TEXT NOT NULL,
    cluster  TEXT NOT NULL,
    scanner  TEXT NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, cluster, scanner),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
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

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_cluster ON scan_results(cluster);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
`

// migrate applies the schema to the database.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("%w: %w", ErrMigrate, err)
	}
	return nil
}
