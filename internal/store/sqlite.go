package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// SQLite implements Store using a SQLite database.
type SQLite struct {
	db *sql.DB
}

// NewSQLite opens or creates a SQLite database at path and runs migrations.
func NewSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", ErrStore, err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db}, nil
}

// Close releases database resources.
func (s *SQLite) Close() error {
	return s.db.Close()
}

// SaveScan persists a complete scan with all per-cluster results.
func (s *SQLite) SaveScan(ctx context.Context, clusters []string, results map[string]map[string]scanner.Result) (string, error) {
	id := generateID()
	now := time.Now().UTC().Format(time.RFC3339)

	scannerNames := collectScannerNames(results)
	clustersJSON, _ := json.Marshal(clusters)
	scannersJSON, _ := json.Marshal(scannerNames)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)",
		id, now, string(clustersJSON), string(scannersJSON))
	if err != nil {
		return "", fmt.Errorf("%w: insert scan: %w", ErrStore, err)
	}

	stmt, err := tx.PrepareContext(ctx,
		"INSERT INTO scan_results (scan_id, cluster, scanner, data_json) VALUES (?, ?, ?, ?)")
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

	// Upsert cluster records.
	for _, cluster := range clusters {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO clusters (name, first_seen, last_seen) VALUES (?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET last_seen = excluded.last_seen`,
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
func (s *SQLite) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, timestamp, clusters, scanners FROM scans WHERE id = ?", id)
	return scanRecordFromRow(row)
}

// ListScans returns scan records ordered by timestamp descending.
func (s *SQLite) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, timestamp, clusters, scanners FROM scans ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		rec, err := scanRecordFromRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

// GetScanResults retrieves all per-cluster scanner results for a scan.
func (s *SQLite) GetScanResults(ctx context.Context, scanID string) (map[string]map[string]scanner.Result, error) {
	rows, err := s.db.QueryContext(ctx,
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
func (s *SQLite) ListClusters(ctx context.Context) ([]ClusterRecord, error) {
	rows, err := s.db.QueryContext(ctx,
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
		c.Groups = s.clusterGroups(ctx, c.Name)
		clusters = append(clusters, c)
	}
	return clusters, rows.Err()
}

// SaveGroup creates or updates a group with the given cluster members.
func (s *SQLite) SaveGroup(ctx context.Context, name string, clusters []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin tx: %w", ErrStore, err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO groups (name) VALUES (?) ON CONFLICT(name) DO NOTHING", name)
	if err != nil {
		return fmt.Errorf("%w: insert group: %w", ErrStore, err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM group_clusters WHERE group_name = ?", name)
	if err != nil {
		return fmt.Errorf("%w: clear group clusters: %w", ErrStore, err)
	}

	for _, cluster := range clusters {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO group_clusters (group_name, cluster_name) VALUES (?, ?)", name, cluster)
		if err != nil {
			return fmt.Errorf("%w: insert group cluster: %w", ErrStore, err)
		}
	}

	return tx.Commit()
}

// GetGroup retrieves a group by name.
func (s *SQLite) GetGroup(ctx context.Context, name string) (*GroupRecord, error) {
	var groupName string
	err := s.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE name = ?", name).Scan(&groupName)
	if err == sql.ErrNoRows {
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
func (s *SQLite) ListGroups(ctx context.Context) ([]GroupRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name FROM groups ORDER BY name")
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
		g.Clusters, _ = s.groupClusters(ctx, g.Name)
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// DeleteGroup removes a group. Cascades to group_clusters.
func (s *SQLite) DeleteGroup(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM groups WHERE name = ?", name)
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
func (s *SQLite) AddClusterToGroup(ctx context.Context, group, cluster string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO group_clusters (group_name, cluster_name) VALUES (?, ?)",
		group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// RemoveClusterFromGroup removes a cluster from a group.
func (s *SQLite) RemoveClusterFromGroup(ctx context.Context, group, cluster string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM group_clusters WHERE group_name = ? AND cluster_name = ?",
		group, cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
	return nil
}

// GetClusterHistory returns scan results for a cluster across scans.
func (s *SQLite) GetClusterHistory(ctx context.Context, cluster string, limit int) ([]ScanResultRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sr.scan_id, sr.cluster, sr.scanner, sr.data_json
		 FROM scan_results sr
		 JOIN scans s ON s.id = sr.scan_id
		 WHERE sr.cluster = ?
		 ORDER BY s.timestamp DESC
		 LIMIT ?`, cluster, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanResultRecord
	for rows.Next() {
		var r ScanResultRecord
		var dataJSON string
		if err := rows.Scan(&r.ScanID, &r.Cluster, &r.Scanner, &dataJSON); err != nil {
			return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
		}
		r.DataJSON = []byte(dataJSON)
		records = append(records, r)
	}
	return records, rows.Err()
}

// GetScansByTimeRange returns scans within a time window.
func (s *SQLite) GetScansByTimeRange(ctx context.Context, start, end time.Time) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, clusters, scanners FROM scans
		 WHERE timestamp >= ? AND timestamp <= ?
		 ORDER BY timestamp DESC`,
		start.Format(time.RFC3339), end.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		rec, err := scanRecordFromRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

// groupClusters returns the cluster names for a group.
func (s *SQLite) groupClusters(ctx context.Context, group string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
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

// clusterGroups returns the group names a cluster belongs to.
func (s *SQLite) clusterGroups(ctx context.Context, cluster string) []string {
	rows, err := s.db.QueryContext(ctx,
		"SELECT group_name FROM group_clusters WHERE cluster_name = ? ORDER BY group_name", cluster)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil {
			groups = append(groups, g)
		}
	}
	return groups
}

// scanRecordFromRow scans a single row into a ScanRecord.
func scanRecordFromRow(row *sql.Row) (*ScanRecord, error) {
	var r ScanRecord
	var ts, clustersJSON, scannersJSON string
	if err := row.Scan(&r.ID, &ts, &clustersJSON, &scannersJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: scan", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %w", ErrQuery, err)
	}
	r.Timestamp, _ = time.Parse(time.RFC3339, ts)
	json.Unmarshal([]byte(clustersJSON), &r.Clusters)
	json.Unmarshal([]byte(scannersJSON), &r.Scanners)
	return &r, nil
}

// scanRecordFromRows scans the current row of a Rows cursor into a ScanRecord.
func scanRecordFromRows(rows *sql.Rows) (*ScanRecord, error) {
	var r ScanRecord
	var ts, clustersJSON, scannersJSON string
	if err := rows.Scan(&r.ID, &ts, &clustersJSON, &scannersJSON); err != nil {
		return nil, fmt.Errorf("%w: scan row: %w", ErrQuery, err)
	}
	r.Timestamp, _ = time.Parse(time.RFC3339, ts)
	json.Unmarshal([]byte(clustersJSON), &r.Clusters)
	json.Unmarshal([]byte(scannersJSON), &r.Scanners)
	return &r, nil
}

// collectScannerNames gathers unique scanner names from results.
func collectScannerNames(results map[string]map[string]scanner.Result) []string {
	seen := make(map[string]struct{})
	for _, scanners := range results {
		for name := range scanners {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// generateID produces a time-sortable unique identifier.
func generateID() string {
	now := time.Now()
	ms := now.UnixMilli()
	r := rand.Int63()
	return fmt.Sprintf("%013d-%016x", ms, r)
}
