package store

import (
	"context"
	"fmt"
	"time"
)

// SetClusterTag upserts one key/value tag on a cluster. Keys are
// case-sensitive and free-form; common conventions are `env=prod`,
// `tier=critical`, `owner=team-a`.
func (s *SQLite) SetClusterTag(ctx context.Context, cluster, key, value string) error {
	if cluster == "" || key == "" {
		return fmt.Errorf("%w: cluster and key required", ErrStore)
	}
	_, err := s.db.ExecContext(ctx, `
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
func (s *SQLite) DeleteClusterTag(ctx context.Context, cluster, key string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM cluster_tags WHERE cluster = ? AND key = ?",
		cluster, key)
	if err != nil {
		return fmt.Errorf("%w: delete cluster tag: %w", ErrStore, err)
	}
	return nil
}

// GetClusterTags returns every tag pair on a cluster.
func (s *SQLite) GetClusterTags(ctx context.Context, cluster string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
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
func (s *SQLite) ListClusterTags(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT cluster, key, value FROM cluster_tags")
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
