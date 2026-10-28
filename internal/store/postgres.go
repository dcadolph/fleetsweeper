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
