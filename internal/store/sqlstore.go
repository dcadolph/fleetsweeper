package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// sqlStore implements the Store methods SQLite and Postgres share. Queries use ? placeholders
// and pass through the dialect's Rebind before they reach the driver.
type sqlStore struct {
	// db is the connection pool.
	db *sql.DB
	// d is the backend's dialect.
	d dialect
}

// rowScanner is the Scan method that *sql.Row and *sql.Rows share.
type rowScanner interface {
	// Scan copies the current row's columns into dest.
	Scan(dest ...any) error
}

// bind rebinds q for the backend, for statements run on a transaction.
func (s *sqlStore) bind(q string) string {
	return s.d.Rebind(q)
}

// exec runs a statement with rebound placeholders.
func (s *sqlStore) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.bind(q), args...)
}

// query runs a query with rebound placeholders.
func (s *sqlStore) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.bind(q), args...)
}

// queryRow runs a single-row query with rebound placeholders.
func (s *sqlStore) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.bind(q), args...)
}

// Ping verifies database connectivity. Used by the server's /readyz endpoint.
func (s *sqlStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Prune deletes scans older than cutoff. The scan_results rows cascade.
// Returns the number of scans deleted.
func (s *sqlStore) Prune(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.exec(ctx,
		"DELETE FROM scans WHERE timestamp < ?", cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("%w: prune: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// SetLocation upserts a manual geographic override for a cluster.
func (s *sqlStore) SetLocation(ctx context.Context, loc LocationRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.exec(ctx,
		`INSERT INTO cluster_locations (cluster, lat, lng, site, notes, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(cluster) DO UPDATE SET
		   lat=excluded.lat, lng=excluded.lng, site=excluded.site, notes=excluded.notes,
		   updated_at=excluded.updated_at`,
		loc.Cluster, loc.Lat, loc.Lng, loc.Site, loc.Notes, now)
	if err != nil {
		return fmt.Errorf("%w: set location: %w", ErrStore, err)
	}
	return nil
}

// GetLocation returns the manual override for a cluster, or nil/no error
// when none has been set.
func (s *sqlStore) GetLocation(ctx context.Context, cluster string) (*LocationRecord, error) {
	row := s.queryRow(ctx,
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
func (s *sqlStore) ListLocations(ctx context.Context) ([]LocationRecord, error) {
	rows, err := s.query(ctx,
		`SELECT cluster, lat, lng, site, notes, updated_at
		 FROM cluster_locations ORDER BY cluster`)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	var out []LocationRecord
	for rows.Next() {
		rec, err := scanLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("%w: scan location: %w", ErrQuery, err)
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// DeleteLocation removes a manual override for a cluster.
func (s *sqlStore) DeleteLocation(ctx context.Context, cluster string) error {
	_, err := s.exec(ctx,
		"DELETE FROM cluster_locations WHERE cluster = ?", cluster)
	if err != nil {
		return fmt.Errorf("%w: delete location: %w", ErrStore, err)
	}
	return nil
}

// scanLocation reads a single cluster_locations row into a LocationRecord.
func scanLocation(row rowScanner) (*LocationRecord, error) {
	var rec LocationRecord
	var updated, site, notes sql.NullString
	if err := row.Scan(&rec.Cluster, &rec.Lat, &rec.Lng, &site, &notes, &updated); err != nil {
		return nil, err
	}
	rec.Site = site.String
	rec.Notes = notes.String
	if updated.Valid {
		t, err := time.Parse(time.RFC3339, updated.String)
		if err == nil {
			rec.UpdatedAt = t
		}
	}
	return &rec, nil
}

// Close releases database resources.
func (s *sqlStore) Close() error {
	return s.db.Close()
}

// SaveScan persists a complete scan with all per-cluster results under a new ID.
func (s *sqlStore) SaveScan(
	ctx context.Context, clusters []string, results map[string]map[string]scanner.Result,
) (string, error) {
	return s.SaveScanRecord(ctx, ScanRecord{Clusters: clusters}, results)
}

// SaveScanRecord persists a scan under rec.ID and rec.Timestamp, generating whichever is unset.
func (s *sqlStore) SaveScanRecord(
	ctx context.Context, rec ScanRecord, results map[string]map[string]scanner.Result,
) (string, error) {
	id := rec.ID
	if id == "" {
		id = generateID()
	}
	ts := rec.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	now := ts.UTC().Format(time.RFC3339)
	clusters := rec.Clusters

	scannerNames := scanner.Names(results)
	clustersJSON, _ := json.Marshal(clusters)
	scannersJSON, _ := json.Marshal(scannerNames)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		s.bind("INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)"),
		id, now, string(clustersJSON), string(scannersJSON))
	if err != nil {
		return "", fmt.Errorf("%w: insert scan: %w", ErrStore, err)
	}

	stmt, err := tx.PrepareContext(ctx, s.bind(
		`INSERT INTO scan_results (scan_id, cluster, scanner, data_json, state, reason)
		 VALUES (?, ?, ?, ?, ?, ?)`))
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
			_, err = stmt.ExecContext(ctx,
				id, cluster, name, string(dataJSON), string(result.State), result.Reason)
			if err != nil {
				return "", fmt.Errorf("%w: insert result: %w", ErrStore, err)
			}
		}
	}

	// Upsert cluster records.
	for _, cluster := range clusters {
		_, err := tx.ExecContext(ctx, s.bind(
			`INSERT INTO clusters (name, first_seen, last_seen) VALUES (?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET last_seen = excluded.last_seen`),
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
func (s *sqlStore) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	row := s.queryRow(ctx,
		"SELECT id, timestamp, clusters, scanners FROM scans WHERE id = ?", id)
	return scanRecord(row)
}

// ListScans returns scan records newest first, breaking timestamp ties by id.
func (s *sqlStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	rows, err := s.query(ctx,
		`SELECT id, timestamp, clusters, scanners FROM scans
		 ORDER BY timestamp DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

// GetScanResults retrieves all per-cluster scanner results for a scan.
func (s *sqlStore) GetScanResults(ctx context.Context, scanID string) (map[string]map[string]scanner.Result, error) {
	rows, err := s.query(ctx,
		`SELECT cluster, scanner, data_json, state, reason FROM scan_results
		 WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	results := make(map[string]map[string]scanner.Result)
	for rows.Next() {
		var cluster, scannerName, dataJSON, state, reason string
		if err := rows.Scan(&cluster, &scannerName, &dataJSON, &state, &reason); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		var data any
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			return nil, fmt.Errorf("%w: unmarshal: %w", ErrQuery, err)
		}
		if results[cluster] == nil {
			results[cluster] = make(map[string]scanner.Result)
		}
		results[cluster][scannerName] = scanner.Result{
			Scanner: scannerName,
			State:   scanner.State(state),
			Reason:  reason,
			Data:    data,
		}
	}
	return results, rows.Err()
}

// ListClusters returns all known clusters with their group memberships.
func (s *sqlStore) ListClusters(ctx context.Context) ([]ClusterRecord, error) {
	rows, err := s.query(ctx,
		"SELECT name, first_seen, last_seen FROM clusters ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var clusters []ClusterRecord
	for rows.Next() {
		var c ClusterRecord
		var firstSeen, lastSeen string
		if err := rows.Scan(&c.Name, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		c.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		c.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		clusters = append(clusters, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	rows.Close()
	_, byCluster, err := s.memberships(ctx)
	if err != nil {
		return nil, err
	}
	for i := range clusters {
		clusters[i].Groups = byCluster[clusters[i].Name]
	}
	return clusters, nil
}

// SaveGroup creates or updates a group with the given cluster members.
func (s *sqlStore) SaveGroup(ctx context.Context, name string, clusters []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		s.bind("INSERT INTO groups (name) VALUES (?) ON CONFLICT(name) DO NOTHING"), name)
	if err != nil {
		return fmt.Errorf("%w: insert group: %w", ErrStore, err)
	}

	_, err = tx.ExecContext(ctx, s.bind("DELETE FROM group_clusters WHERE group_name = ?"), name)
	if err != nil {
		return fmt.Errorf("%w: clear group clusters: %w", ErrStore, err)
	}

	for _, cluster := range clusters {
		_, err = tx.ExecContext(ctx,
			s.bind("INSERT INTO group_clusters (group_name, cluster_name) VALUES (?, ?)"),
			name, cluster)
		if err != nil {
			return fmt.Errorf("%w: insert group cluster: %w", ErrStore, err)
		}
	}

	return tx.Commit()
}

// GetGroup retrieves a group by name.
func (s *sqlStore) GetGroup(ctx context.Context, name string) (*GroupRecord, error) {
	var groupName string
	err := s.queryRow(ctx, "SELECT name FROM groups WHERE name = ?", name).Scan(&groupName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: group %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}

	clusters, err := s.groupClusters(ctx, name)
	if err != nil {
		return nil, err
	}
	return &GroupRecord{Name: groupName, Clusters: clusters}, nil
}

// ListGroups returns all groups.
func (s *sqlStore) ListGroups(ctx context.Context) ([]GroupRecord, error) {
	rows, err := s.query(ctx, "SELECT name FROM groups ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var groups []GroupRecord
	for rows.Next() {
		var g GroupRecord
		if err := rows.Scan(&g.Name); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	rows.Close()
	byGroup, _, err := s.memberships(ctx)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		groups[i].Clusters = byGroup[groups[i].Name]
	}
	return groups, nil
}

// DeleteGroup removes a group. Cascades to group_clusters.
func (s *sqlStore) DeleteGroup(ctx context.Context, name string) error {
	res, err := s.exec(ctx, "DELETE FROM groups WHERE name = ?", name)
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
func (s *sqlStore) AddClusterToGroup(ctx context.Context, group, cluster string) error {
	_, err := s.exec(ctx,
		`INSERT INTO group_clusters (group_name, cluster_name) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`,
		group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// RemoveClusterFromGroup removes a cluster from a group.
func (s *sqlStore) RemoveClusterFromGroup(ctx context.Context, group, cluster string) error {
	_, err := s.exec(ctx,
		"DELETE FROM group_clusters WHERE group_name = ? AND cluster_name = ?",
		group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// GetClusterHistory returns scan results for a cluster across scans.
func (s *sqlStore) GetClusterHistory(ctx context.Context, cluster string, limit int) ([]ScanResultRecord, error) {
	rows, err := s.query(ctx,
		`SELECT sr.scan_id, sr.cluster, sr.scanner, sr.data_json, sr.state, sr.reason
		 FROM scan_results sr
		 JOIN scans s ON s.id = sr.scan_id
		 WHERE sr.cluster = ?
		 ORDER BY s.timestamp DESC, s.id DESC
		 LIMIT ?`, cluster, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanResultRecord
	for rows.Next() {
		var r ScanResultRecord
		var dataJSON, state string
		err := rows.Scan(&r.ScanID, &r.Cluster, &r.Scanner, &dataJSON, &state, &r.Reason)
		if err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		r.DataJSON = []byte(dataJSON)
		r.State = scanner.State(state)
		records = append(records, r)
	}
	return records, rows.Err()
}

// GetScansByTimeRange returns scans within a time window.
func (s *sqlStore) GetScansByTimeRange(ctx context.Context, start, end time.Time) ([]ScanRecord, error) {
	rows, err := s.query(ctx,
		`SELECT id, timestamp, clusters, scanners FROM scans
		 WHERE timestamp >= ? AND timestamp <= ?
		 ORDER BY timestamp DESC, id DESC`,
		start.Format(time.RFC3339), end.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

// groupClusters returns the cluster names for a group.
func (s *sqlStore) groupClusters(ctx context.Context, group string) ([]string, error) {
	rows, err := s.query(ctx,
		"SELECT cluster_name FROM group_clusters WHERE group_name = ? ORDER BY cluster_name", group)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var clusters []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		clusters = append(clusters, c)
	}
	return clusters, rows.Err()
}

// memberships returns every group's clusters and every cluster's groups, each list sorted, in
// one query. Callers read their own rows to the end first: a nested query while rows are open
// waits on a second connection, which an in-memory store, held to one, never has.
func (s *sqlStore) memberships(ctx context.Context) (byGroup, byCluster map[string][]string, err error) {
	rows, err := s.query(ctx,
		"SELECT group_name, cluster_name FROM group_clusters ORDER BY group_name, cluster_name")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()
	return scanMemberships(rows)
}

// scanRecord reads one scans row into a ScanRecord. A missing single row maps to ErrNotFound.
func scanRecord(row rowScanner) (*ScanRecord, error) {
	var r ScanRecord
	var ts, clustersJSON, scannersJSON string
	if err := row.Scan(&r.ID, &ts, &clustersJSON, &scannersJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: scan", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
	}
	ts2, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("%w: parse timestamp: %w", ErrQuery, err)
	}
	r.Timestamp = ts2
	if err := json.Unmarshal([]byte(clustersJSON), &r.Clusters); err != nil {
		return nil, fmt.Errorf("%w: unmarshal clusters: %w", ErrQuery, err)
	}
	if err := json.Unmarshal([]byte(scannersJSON), &r.Scanners); err != nil {
		return nil, fmt.Errorf("%w: unmarshal scanners: %w", ErrQuery, err)
	}
	return &r, nil
}

// generateID produces a time-sortable unique identifier. The leading millisecond
// timestamp keeps natural sort order; the random suffix uses crypto/rand so
// concurrent scan triggers cannot collide.
func generateID() string {
	ms := time.Now().UnixMilli()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should not fail on supported platforms; fall back to
		// the timestamp alone so the caller still gets a usable ID.
		binary.BigEndian.PutUint64(b[:], uint64(ms))
	}
	return fmt.Sprintf("%013d-%s", ms, hex.EncodeToString(b[:]))
}
