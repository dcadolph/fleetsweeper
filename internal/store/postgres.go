package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Postgres implements Store against a PostgreSQL database. It is functionally
// equivalent to SQLite but tolerates concurrent writers, so multi-replica
// fleetsweeper deployments share a single backend. Timestamps are stored as
// RFC3339 TEXT and JSON columns as TEXT so the same row marshaling code as
// SQLite continues to work; the performance cost is negligible at the row
// volumes Fleetsweeper produces.
type Postgres struct {
	// sqlStore holds the queries Postgres shares with SQLite.
	sqlStore
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

	if err := migratePostgres(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Postgres{sqlStore{db: db, d: postgresDialect}}, nil
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

// Vacuum is a no-op on Postgres because autovacuum runs in the background.
// The method exists so the Store interface stays uniform.
func (p *Postgres) Vacuum(_ context.Context) error {
	return nil
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
		rec.ID, rec.Timestamp.UTC().Format(sortableTime),
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
		cutoff.UTC().Format(sortableTime))
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
		args = append(args, opts.Since.UTC().Format(sortableTime))
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
		rec.ReceivedAt.UTC().Format(sortableTime),
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
		args = append(args, opts.Since.UTC().Format(sortableTime))
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
		cutoff.UTC().Format(sortableTime))
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
