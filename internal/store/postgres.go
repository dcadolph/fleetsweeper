package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Postgres implements Store against a PostgreSQL database. It is functionally
// equivalent to SQLite but tolerates concurrent writers, so multi-replica
// fleetsweeper deployments share a single backend. Timestamps are stored as
// RFC3339 TEXT and JSON columns as TEXT so the same row marshalling code as
// SQLite continues to work; the performance cost is negligible at the row
// volumes Fleetsweeper produces.
type Postgres struct {
	db *sql.DB
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

	if err := migratePostgres(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Postgres{db: db}, nil
}

// Ping verifies database connectivity. Used by the server's /readyz endpoint.
func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// Close releases connection pool resources.
func (p *Postgres) Close() error {
	return p.db.Close()
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

// exec is a small wrapper around db.ExecContext that rebinds placeholders.
func (p *Postgres) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return p.db.ExecContext(ctx, rebind(q), args...)
}

// query is a small wrapper around db.QueryContext that rebinds placeholders.
func (p *Postgres) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return p.db.QueryContext(ctx, rebind(q), args...)
}

// queryRow is a small wrapper around db.QueryRowContext that rebinds placeholders.
func (p *Postgres) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return p.db.QueryRowContext(ctx, rebind(q), args...)
}

// Prune deletes scans older than cutoff. The scan_results rows cascade.
func (p *Postgres) Prune(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := p.exec(ctx,
		"DELETE FROM scans WHERE timestamp < ?", cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("%w: prune: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Vacuum is a no-op on Postgres because autovacuum runs in the background.
// The method exists so the Store interface stays uniform.
func (p *Postgres) Vacuum(_ context.Context) error {
	return nil
}

// SetLocation upserts a manual geographic override for a cluster.
func (p *Postgres) SetLocation(ctx context.Context, loc LocationRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := p.exec(ctx,
		`INSERT INTO cluster_locations (cluster, lat, lng, site, notes, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (cluster) DO UPDATE SET
		   lat = EXCLUDED.lat, lng = EXCLUDED.lng,
		   site = EXCLUDED.site, notes = EXCLUDED.notes,
		   updated_at = EXCLUDED.updated_at`,
		loc.Cluster, loc.Lat, loc.Lng, loc.Site, loc.Notes, now)
	if err != nil {
		return fmt.Errorf("%w: set location: %w", ErrStore, err)
	}
	return nil
}

// GetLocation returns the manual override for a cluster, or nil/no error
// when none has been set.
func (p *Postgres) GetLocation(ctx context.Context, cluster string) (*LocationRecord, error) {
	row := p.queryRow(ctx,
		`SELECT cluster, lat, lng, site, notes, updated_at
		 FROM cluster_locations WHERE cluster = ?`, cluster)
	rec, err := scanLocation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	return rec, nil
}

// ListLocations returns every manual override sorted by cluster name.
func (p *Postgres) ListLocations(ctx context.Context) ([]LocationRecord, error) {
	rows, err := p.query(ctx,
		`SELECT cluster, lat, lng, site, notes, updated_at
		 FROM cluster_locations ORDER BY cluster`)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []LocationRecord
	for rows.Next() {
		var rec LocationRecord
		var updated, site, notes sql.NullString
		if err := rows.Scan(&rec.Cluster, &rec.Lat, &rec.Lng, &site, &notes, &updated); err != nil {
			return nil, fmt.Errorf("%w: scan location: %w", ErrQuery, err)
		}
		rec.Site = site.String
		rec.Notes = notes.String
		if updated.Valid {
			if t, err := time.Parse(time.RFC3339, updated.String); err == nil {
				rec.UpdatedAt = t
			}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DeleteLocation removes a manual override for a cluster.
func (p *Postgres) DeleteLocation(ctx context.Context, cluster string) error {
	_, err := p.exec(ctx,
		"DELETE FROM cluster_locations WHERE cluster = ?", cluster)
	if err != nil {
		return fmt.Errorf("%w: delete location: %w", ErrStore, err)
	}
	return nil
}

// SaveScan persists a complete scan with all per-cluster results.
func (p *Postgres) SaveScan(ctx context.Context, clusters []string, results map[string]map[string]scanner.Result) (string, error) {
	id := generateID()
	now := time.Now().UTC().Format(time.RFC3339)

	scannerNames := collectScannerNames(results)
	clustersJSON, _ := json.Marshal(clusters)
	scannersJSON, _ := json.Marshal(scannerNames)

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, rebind(
		"INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)"),
		id, now, string(clustersJSON), string(scannersJSON))
	if err != nil {
		return "", fmt.Errorf("%w: insert scan: %w", ErrStore, err)
	}

	stmt, err := tx.PrepareContext(ctx, rebind(
		"INSERT INTO scan_results (scan_id, cluster, scanner, data_json) VALUES (?, ?, ?, ?)"))
	if err != nil {
		return "", fmt.Errorf("%w: prepare: %w", ErrStore, err)
	}
	defer stmt.Close()

	for cluster, scanners := range results {
		for name, result := range scanners {
			dataJSON, err := json.Marshal(result.Data)
			if err != nil {
				return "", fmt.Errorf("%w: marshal data: %w", ErrStore, err)
			}
			if _, err := stmt.ExecContext(ctx, id, cluster, name, string(dataJSON)); err != nil {
				return "", fmt.Errorf("%w: insert result: %w", ErrStore, err)
			}
		}
	}

	for _, cluster := range clusters {
		_, err := tx.ExecContext(ctx, rebind(
			`INSERT INTO clusters (name, first_seen, last_seen) VALUES (?, ?, ?)
			 ON CONFLICT (name) DO UPDATE SET last_seen = EXCLUDED.last_seen`),
			cluster, now, now)
		if err != nil {
			return "", fmt.Errorf("%w: upsert cluster: %w", ErrStore, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("%w: commit: %w", ErrStore, err)
	}
	return id, nil
}

// GetScan retrieves a scan record by ID.
func (p *Postgres) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	row := p.queryRow(ctx,
		"SELECT id, timestamp, clusters, scanners FROM scans WHERE id = ?", id)
	return scanRecordFromRow(row)
}

// ListScans returns scan records newest first, breaking timestamp ties by id.
func (p *Postgres) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	rows, err := p.query(ctx,
		"SELECT id, timestamp, clusters, scanners FROM scans ORDER BY timestamp DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []ScanRecord
	for rows.Next() {
		rec, err := scanRecordFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// GetScanResults retrieves all per-cluster scanner results for a scan.
func (p *Postgres) GetScanResults(ctx context.Context, scanID string) (map[string]map[string]scanner.Result, error) {
	rows, err := p.query(ctx,
		"SELECT cluster, scanner, data_json FROM scan_results WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	results := make(map[string]map[string]scanner.Result)
	for rows.Next() {
		var cluster, scannerName, dataJSON string
		if err := rows.Scan(&cluster, &scannerName, &dataJSON); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		var data any
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			return nil, fmt.Errorf("%w: unmarshal: %w", ErrQuery, err)
		}
		if results[cluster] == nil {
			results[cluster] = make(map[string]scanner.Result)
		}
		results[cluster][scannerName] = scanner.Result{Scanner: scannerName, Data: data}
	}
	return results, rows.Err()
}

// ListClusters returns all known clusters with their group memberships.
func (p *Postgres) ListClusters(ctx context.Context) ([]ClusterRecord, error) {
	rows, err := p.query(ctx, "SELECT name, first_seen, last_seen FROM clusters ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []ClusterRecord
	for rows.Next() {
		var c ClusterRecord
		var firstSeen, lastSeen string
		if err := rows.Scan(&c.Name, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		c.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		c.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		c.Groups = p.clusterGroups(ctx, c.Name)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveGroup creates or updates a group with the given cluster members.
func (p *Postgres) SaveGroup(ctx context.Context, name string, clusters []string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, rebind(
		"INSERT INTO groups (name) VALUES (?) ON CONFLICT (name) DO NOTHING"), name); err != nil {
		return fmt.Errorf("%w: insert group: %w", ErrStore, err)
	}
	if _, err := tx.ExecContext(ctx, rebind(
		"DELETE FROM group_clusters WHERE group_name = ?"), name); err != nil {
		return fmt.Errorf("%w: clear group clusters: %w", ErrStore, err)
	}
	for _, cluster := range clusters {
		if _, err := tx.ExecContext(ctx, rebind(
			"INSERT INTO group_clusters (group_name, cluster_name) VALUES (?, ?)"),
			name, cluster); err != nil {
			return fmt.Errorf("%w: insert group cluster: %w", ErrStore, err)
		}
	}
	return tx.Commit()
}

// GetGroup retrieves a group by name.
func (p *Postgres) GetGroup(ctx context.Context, name string) (*GroupRecord, error) {
	var groupName string
	err := p.queryRow(ctx, "SELECT name FROM groups WHERE name = ?", name).Scan(&groupName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: group %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	clusters, err := p.groupClusters(ctx, name)
	if err != nil {
		return nil, err
	}
	return &GroupRecord{Name: groupName, Clusters: clusters}, nil
}

// ListGroups returns all groups.
func (p *Postgres) ListGroups(ctx context.Context) ([]GroupRecord, error) {
	rows, err := p.query(ctx, "SELECT name FROM groups ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []GroupRecord
	for rows.Next() {
		var g GroupRecord
		if err := rows.Scan(&g.Name); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		g.Clusters, _ = p.groupClusters(ctx, g.Name)
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteGroup removes a group. Cascades to group_clusters.
func (p *Postgres) DeleteGroup(ctx context.Context, name string) error {
	res, err := p.exec(ctx, "DELETE FROM groups WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: group %s", ErrNotFound, name)
	}
	return nil
}

// AddClusterToGroup adds a cluster to an existing group.
func (p *Postgres) AddClusterToGroup(ctx context.Context, group, cluster string) error {
	_, err := p.exec(ctx,
		"INSERT INTO group_clusters (group_name, cluster_name) VALUES (?, ?) ON CONFLICT DO NOTHING",
		group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// RemoveClusterFromGroup removes a cluster from a group.
func (p *Postgres) RemoveClusterFromGroup(ctx context.Context, group, cluster string) error {
	_, err := p.exec(ctx,
		"DELETE FROM group_clusters WHERE group_name = ? AND cluster_name = ?", group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// GetClusterHistory returns scan results for a cluster across scans.
func (p *Postgres) GetClusterHistory(ctx context.Context, cluster string, limit int) ([]ScanResultRecord, error) {
	rows, err := p.query(ctx, `
SELECT sr.scan_id, sr.cluster, sr.scanner, sr.data_json
FROM scan_results sr
JOIN scans s ON s.id = sr.scan_id
WHERE sr.cluster = ?
ORDER BY s.timestamp DESC, s.id DESC
LIMIT ?`, cluster, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []ScanResultRecord
	for rows.Next() {
		var r ScanResultRecord
		var dataJSON string
		if err := rows.Scan(&r.ScanID, &r.Cluster, &r.Scanner, &dataJSON); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		r.DataJSON = []byte(dataJSON)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetScansByTimeRange returns scans within a time window.
func (p *Postgres) GetScansByTimeRange(ctx context.Context, start, end time.Time) ([]ScanRecord, error) {
	rows, err := p.query(ctx, `
SELECT id, timestamp, clusters, scanners FROM scans
WHERE timestamp >= ? AND timestamp <= ?
ORDER BY timestamp DESC, id DESC`,
		start.Format(time.RFC3339), end.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []ScanRecord
	for rows.Next() {
		rec, err := scanRecordFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// groupClusters returns the cluster names for a group.
func (p *Postgres) groupClusters(ctx context.Context, group string) ([]string, error) {
	rows, err := p.query(ctx,
		"SELECT cluster_name FROM group_clusters WHERE group_name = ? ORDER BY cluster_name", group)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrQuery, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// clusterGroups returns the group names a cluster belongs to.
func (p *Postgres) clusterGroups(ctx context.Context, cluster string) []string {
	rows, err := p.query(ctx,
		"SELECT group_name FROM group_clusters WHERE cluster_name = ? ORDER BY group_name", cluster)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil {
			out = append(out, g)
		}
	}
	return out
}

// SaveAck upserts an acknowledgement.
func (p *Postgres) SaveAck(ctx context.Context, rec AckRecord) error {
	if rec.Fingerprint == "" {
		return errors.New("ack: fingerprint required")
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	var snoozeStr sql.NullString
	if !rec.SnoozeUntil.IsZero() {
		snoozeStr = sql.NullString{String: rec.SnoozeUntil.UTC().Format(time.RFC3339), Valid: true}
	}
	_, err := p.exec(ctx, `
INSERT INTO finding_acks (fingerprint, cluster, scanner, title, ack_by, reason, snooze_until, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (fingerprint) DO UPDATE SET
    cluster      = EXCLUDED.cluster,
    scanner      = EXCLUDED.scanner,
    title        = EXCLUDED.title,
    ack_by       = EXCLUDED.ack_by,
    reason       = EXCLUDED.reason,
    snooze_until = EXCLUDED.snooze_until,
    created_at   = EXCLUDED.created_at`,
		rec.Fingerprint, rec.Cluster, rec.Scanner, rec.Title,
		rec.AckBy, rec.Reason, snoozeStr, rec.CreatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("%w: save ack: %w", ErrStore, err)
	}
	return nil
}

// DeleteAck removes an acknowledgement by fingerprint. Idempotent.
func (p *Postgres) DeleteAck(ctx context.Context, fingerprint string) error {
	_, err := p.exec(ctx, "DELETE FROM finding_acks WHERE fingerprint = ?", fingerprint)
	if err != nil {
		return fmt.Errorf("%w: delete ack: %w", ErrStore, err)
	}
	return nil
}

// ListAcks returns every active ack with expired snoozes filtered out.
func (p *Postgres) ListAcks(ctx context.Context) ([]AckRecord, error) {
	if err := p.pruneExpiredAcks(ctx); err != nil {
		return nil, err
	}
	rows, err := p.query(ctx, `
SELECT fingerprint, cluster, scanner, title, ack_by, reason, snooze_until, created_at
FROM finding_acks
ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("%w: list acks: %w", ErrStore, err)
	}
	defer rows.Close()
	var out []AckRecord
	for rows.Next() {
		r, err := scanAckRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IsAcked reports whether a finding has an active ack.
func (p *Postgres) IsAcked(ctx context.Context, fingerprint string) (bool, error) {
	if err := p.pruneExpiredAcks(ctx); err != nil {
		return false, err
	}
	var n int
	err := p.queryRow(ctx,
		"SELECT COUNT(1) FROM finding_acks WHERE fingerprint = ?", fingerprint,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("%w: is acked: %w", ErrStore, err)
	}
	return n > 0, nil
}

// pruneExpiredAcks deletes acks whose snooze has elapsed.
func (p *Postgres) pruneExpiredAcks(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := p.exec(ctx,
		"DELETE FROM finding_acks WHERE snooze_until IS NOT NULL AND snooze_until <> '' AND snooze_until < ?",
		now)
	if err != nil {
		return fmt.Errorf("%w: prune expired acks: %w", ErrStore, err)
	}
	return nil
}

// SaveAPIKey inserts a new API key.
func (p *Postgres) SaveAPIKey(ctx context.Context, rec APIKeyRecord) error {
	if rec.ID == "" || rec.TokenHash == "" {
		return errors.New("api key: id and token hash required")
	}
	if !ValidRole(rec.Role) {
		return fmt.Errorf("api key: invalid role %q", rec.Role)
	}
	if len(rec.ClusterScope) == 0 {
		rec.ClusterScope = []string{ScopeWildcard}
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	scopeJSON, err := json.Marshal(rec.ClusterScope)
	if err != nil {
		return fmt.Errorf("%w: marshal scope: %w", ErrStore, err)
	}
	var expires, lastUsed, revoked sql.NullString
	if !rec.ExpiresAt.IsZero() {
		expires = sql.NullString{String: rec.ExpiresAt.UTC().Format(time.RFC3339), Valid: true}
	}
	if !rec.LastUsedAt.IsZero() {
		lastUsed = sql.NullString{String: rec.LastUsedAt.UTC().Format(time.RFC3339), Valid: true}
	}
	if !rec.RevokedAt.IsZero() {
		revoked = sql.NullString{String: rec.RevokedAt.UTC().Format(time.RFC3339), Valid: true}
	}
	_, err = p.exec(ctx, `
INSERT INTO api_keys (id, token_hash, name, role, cluster_scope, created_at, expires_at, last_used_at, revoked_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.TokenHash, rec.Name, rec.Role, string(scopeJSON),
		rec.CreatedAt.UTC().Format(time.RFC3339), expires, lastUsed, revoked, rec.CreatedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			return fmt.Errorf("%w: duplicate api key", ErrStore)
		}
		return fmt.Errorf("%w: save api key: %w", ErrStore, err)
	}
	return nil
}

// GetAPIKeyByHash looks up a key by token hash.
func (p *Postgres) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error) {
	row := p.queryRow(ctx, `
SELECT id, token_hash, name, role, cluster_scope, created_at, expires_at, last_used_at, revoked_at, created_by
FROM api_keys WHERE token_hash = ?`, hash)
	rec, err := scanAPIKeyRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: api key", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: get api key: %w", ErrQuery, err)
	}
	return rec, nil
}

// GetAPIKey returns the key with the given ID.
func (p *Postgres) GetAPIKey(ctx context.Context, id string) (*APIKeyRecord, error) {
	row := p.queryRow(ctx, `
SELECT id, token_hash, name, role, cluster_scope, created_at, expires_at, last_used_at, revoked_at, created_by
FROM api_keys WHERE id = ?`, id)
	rec, err := scanAPIKeyRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: api key %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: get api key: %w", ErrQuery, err)
	}
	return rec, nil
}

// ListAPIKeys returns every API key.
func (p *Postgres) ListAPIKeys(ctx context.Context) ([]APIKeyRecord, error) {
	rows, err := p.query(ctx, `
SELECT id, token_hash, name, role, cluster_scope, created_at, expires_at, last_used_at, revoked_at, created_by
FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("%w: list api keys: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []APIKeyRecord
	for rows.Next() {
		rec, err := scanAPIKeyRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks a key as revoked.
func (p *Postgres) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := p.exec(ctx,
		"UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("%w: revoke api key: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: api key %s", ErrNotFound, id)
	}
	return nil
}

// TouchAPIKey records the last-used-at timestamp.
func (p *Postgres) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	_, err := p.exec(ctx, "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
		at.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("%w: touch api key: %w", ErrStore, err)
	}
	return nil
}

// SaveAuditEntry inserts one audit entry.
func (p *Postgres) SaveAuditEntry(ctx context.Context, rec AuditEntry) error {
	if rec.ID == "" {
		rec.ID = generateID()
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	_, err := p.exec(ctx, `
INSERT INTO audit_log (id, timestamp, actor_id, actor_name, actor_role, method, path, status, remote_addr, user_agent, duration_ms, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp.UTC().Format(time.RFC3339Nano),
		nullable(rec.ActorID), nullable(rec.ActorName), nullable(rec.ActorRole),
		rec.Method, rec.Path, rec.Status,
		nullable(rec.RemoteAddr), nullable(rec.UserAgent),
		rec.DurationMS, nullable(rec.Error),
	)
	if err != nil {
		return fmt.Errorf("%w: save audit entry: %w", ErrStore, err)
	}
	return nil
}

// PruneAuditEntries deletes audit_log rows older than cutoff. Returns the
// number of rows removed. Idempotent; safe to call from a periodic ticker.
func (p *Postgres) PruneAuditEntries(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := p.exec(ctx,
		"DELETE FROM audit_log WHERE timestamp < ?",
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("%w: prune audit: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListAuditEntries returns audit entries matching opts.
func (p *Postgres) ListAuditEntries(ctx context.Context, opts AuditListOptions) ([]AuditEntry, error) {
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	var (
		clauses []string
		args    []any
	)
	if !opts.Since.IsZero() {
		clauses = append(clauses, "timestamp > ?")
		args = append(args, opts.Since.UTC().Format(time.RFC3339Nano))
	}
	if opts.ActorID != "" {
		clauses = append(clauses, "actor_id = ?")
		args = append(args, opts.ActorID)
	}
	if opts.MinStatus > 0 {
		clauses = append(clauses, "status >= ?")
		args = append(args, opts.MinStatus)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, opts.Limit)
	rows, err := p.query(ctx, `
SELECT id, timestamp, actor_id, actor_name, actor_role, method, path, status, remote_addr, user_agent, duration_ms, error
FROM audit_log`+where+` ORDER BY timestamp DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: list audit: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		rec, err := scanAuditRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// UpsertAlert inserts or updates an alert keyed by fingerprint.
func (p *Postgres) UpsertAlert(ctx context.Context, rec AlertRecord) error {
	if rec.Fingerprint == "" {
		return fmt.Errorf("%w: alert fingerprint required", ErrStore)
	}
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	labelsJSON, err := json.Marshal(rec.Labels)
	if err != nil {
		return fmt.Errorf("%w: marshal labels: %w", ErrStore, err)
	}
	annJSON, err := json.Marshal(rec.Annotations)
	if err != nil {
		return fmt.Errorf("%w: marshal annotations: %w", ErrStore, err)
	}
	_, err = p.exec(ctx, `
INSERT INTO alerts (fingerprint, cluster, status, alertname, severity, summary, starts_at, ends_at, received_at, labels_json, annotations_json, generator_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(fingerprint) DO UPDATE SET
    cluster = excluded.cluster,
    status = excluded.status,
    alertname = excluded.alertname,
    severity = excluded.severity,
    summary = excluded.summary,
    starts_at = excluded.starts_at,
    ends_at = excluded.ends_at,
    received_at = excluded.received_at,
    labels_json = excluded.labels_json,
    annotations_json = excluded.annotations_json,
    generator_url = excluded.generator_url`,
		rec.Fingerprint, rec.Cluster, rec.Status, rec.AlertName,
		nullable(rec.Severity), nullable(rec.Summary),
		nullableTime(rec.StartsAt), nullableTime(rec.EndsAt),
		rec.ReceivedAt.UTC().Format(time.RFC3339Nano),
		string(labelsJSON), string(annJSON),
		nullable(rec.GeneratorURL),
	)
	if err != nil {
		return fmt.Errorf("%w: upsert alert: %w", ErrStore, err)
	}
	return nil
}

// GetAlert returns the alert row with the given fingerprint. Returns
// the wrapped ErrNotFound when no row matches.
func (p *Postgres) GetAlert(ctx context.Context, fingerprint string) (*AlertRecord, error) {
	rows, err := p.query(ctx, `
SELECT fingerprint, cluster, status, alertname, severity, summary, starts_at, ends_at, received_at, labels_json, annotations_json, generator_url
FROM alerts WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("%w: get alert: %w", ErrQuery, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrNotFound
	}
	r, err := scanAlertRow(rows)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListAlerts returns alerts matching opts, newest received_at first.
func (p *Postgres) ListAlerts(ctx context.Context, opts AlertListOptions) ([]AlertRecord, error) {
	if opts.Limit <= 0 {
		opts.Limit = 200
	}
	var (
		clauses []string
		args    []any
	)
	if opts.Cluster != "" {
		clauses = append(clauses, "cluster = ?")
		args = append(args, opts.Cluster)
	}
	if opts.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, opts.Status)
	}
	if opts.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, opts.Severity)
	}
	if !opts.Since.IsZero() {
		clauses = append(clauses, "received_at > ?")
		args = append(args, opts.Since.UTC().Format(time.RFC3339Nano))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, opts.Limit)
	rows, err := p.query(ctx, `
SELECT fingerprint, cluster, status, alertname, severity, summary, starts_at, ends_at, received_at, labels_json, annotations_json, generator_url
FROM alerts`+where+` ORDER BY received_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: list alerts: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []AlertRecord
	for rows.Next() {
		rec, err := scanAlertRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// PruneAlerts deletes alert rows older than cutoff. Returns rows removed.
func (p *Postgres) PruneAlerts(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := p.exec(ctx,
		"DELETE FROM alerts WHERE received_at < ?",
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("%w: prune alerts: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// SetClusterTag upserts one key/value tag on a cluster.
func (p *Postgres) SetClusterTag(ctx context.Context, cluster, key, value string) error {
	if cluster == "" || key == "" {
		return fmt.Errorf("%w: cluster and key required", ErrStore)
	}
	_, err := p.exec(ctx, `
INSERT INTO cluster_tags (cluster, key, value, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(cluster, key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at`,
		cluster, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("%w: set cluster tag: %w", ErrStore, err)
	}
	return nil
}

// DeleteClusterTag removes one key from a cluster's tag set.
func (p *Postgres) DeleteClusterTag(ctx context.Context, cluster, key string) error {
	_, err := p.exec(ctx,
		"DELETE FROM cluster_tags WHERE cluster = ? AND key = ?",
		cluster, key)
	if err != nil {
		return fmt.Errorf("%w: delete cluster tag: %w", ErrStore, err)
	}
	return nil
}

// GetClusterTags returns every tag pair on a cluster.
func (p *Postgres) GetClusterTags(ctx context.Context, cluster string) (map[string]string, error) {
	rows, err := p.query(ctx,
		"SELECT key, value FROM cluster_tags WHERE cluster = ?",
		cluster)
	if err != nil {
		return nil, fmt.Errorf("%w: get cluster tags: %w", ErrQuery, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("%w: scan tag row: %w", ErrQuery, err)
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ListClusterTags returns every tag across the fleet, grouped by cluster.
func (p *Postgres) ListClusterTags(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := p.query(ctx, "SELECT cluster, key, value FROM cluster_tags")
	if err != nil {
		return nil, fmt.Errorf("%w: list cluster tags: %w", ErrQuery, err)
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var c, k, v string
		if err := rows.Scan(&c, &k, &v); err != nil {
			return nil, fmt.Errorf("%w: scan tag row: %w", ErrQuery, err)
		}
		if out[c] == nil {
			out[c] = map[string]string{}
		}
		out[c][k] = v
	}
	return out, rows.Err()
}

// orderedClusters returns the input list sorted for deterministic output.
// Postgres uses this helper to keep its row scan loops stable for testing.
func orderedClusters(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

var _ = orderedClusters // reserved for future use; keeps the helper accessible.
