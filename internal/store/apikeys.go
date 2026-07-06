package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APIKeyRecord is a persisted API key authorised to call the server.
// Tokens are never stored in plaintext: only TokenHash is persisted, and the
// raw token is returned to the operator exactly once at creation time.
type APIKeyRecord struct {
	// ID is the stable identifier used in audit log entries and revocation calls.
	ID string `json:"id"`
	// TokenHash is the lowercase-hex SHA-256 of the raw token.
	TokenHash string `json:"-"`
	// Name is a human-readable label for the key (for example "ci-runner").
	Name string `json:"name"`
	// Role is the authorisation role: admin, operator, or viewer.
	Role string `json:"role"`
	// ClusterScope lists cluster names (or "group:<name>" entries) this key may
	// act on. The single element "*" grants unrestricted access.
	ClusterScope []string `json:"cluster_scope"`
	// CreatedAt is when the key was minted.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt, when non-zero, is when the key automatically becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`
	// LastUsedAt is the most recent successful authentication.
	LastUsedAt time.Time `json:"last_used_at"`
	// RevokedAt, when non-zero, marks the key as administratively disabled.
	RevokedAt time.Time `json:"revoked_at"`
	// CreatedBy identifies the actor that created this key (admin key id, or
	// "bootstrap" for the legacy --auth-token, or "cli" for offline creation).
	CreatedBy string `json:"created_by,omitempty"`
}

// Role enumerates the authorisation levels Fleetsweeper recognizes.
const (
	// RoleAdmin grants unrestricted access including key management and audit log.
	RoleAdmin = "admin"
	// RoleOperator may trigger scans and mutate findings within scope.
	RoleOperator = "operator"
	// RoleViewer may only read.
	RoleViewer = "viewer"
)

// ScopeWildcard is the cluster scope entry that grants access to every cluster.
const ScopeWildcard = "*"

// ValidRole reports whether the provided string is one of the recognized roles.
func ValidRole(r string) bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

// HashToken returns the lowercase-hex SHA-256 of a raw token. Used both at
// creation time (when persisting) and on each request (when matching).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateToken returns a freshly minted token suitable for an API key. The
// "fsk_" prefix lets operators identify a Fleetsweeper key at a glance in logs
// and secret stores. The remaining 32 bytes come from crypto/rand.
func GenerateToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("%w: generate token: %w", ErrStore, err)
	}
	return "fsk_" + hex.EncodeToString(buf[:]), nil
}

// TokensEqual compares two raw tokens in constant time to defeat timing oracles.
func TokensEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SaveAPIKey inserts a new API key. The ID and TokenHash must already be set;
// CreatedAt defaults to now when zero. Re-inserting the same ID returns ErrStore.
func (s *SQLite) SaveAPIKey(ctx context.Context, rec APIKeyRecord) error {
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
	_, err = s.db.ExecContext(ctx, `
INSERT INTO api_keys (id, token_hash, name, role, cluster_scope, created_at, expires_at, last_used_at, revoked_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.TokenHash, rec.Name, rec.Role, string(scopeJSON),
		rec.CreatedAt.UTC().Format(time.RFC3339), expires, lastUsed, revoked, rec.CreatedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("%w: duplicate api key", ErrStore)
		}
		return fmt.Errorf("%w: save api key: %w", ErrStore, err)
	}
	return nil
}

// GetAPIKeyByHash looks up a key by its token hash. Revoked or expired keys
// are returned with their RevokedAt/ExpiresAt set so callers can produce the
// right error message.
func (s *SQLite) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error) {
	row := s.db.QueryRowContext(ctx, `
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
func (s *SQLite) GetAPIKey(ctx context.Context, id string) (*APIKeyRecord, error) {
	row := s.db.QueryRowContext(ctx, `
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

// ListAPIKeys returns every API key, ordered by creation time descending.
// Revoked keys are included so administrators can audit them.
func (s *SQLite) ListAPIKeys(ctx context.Context) ([]APIKeyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
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

// RevokeAPIKey marks a key as revoked. The row is retained so audit log
// entries referencing it remain interpretable.
func (s *SQLite) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
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

// TouchAPIKey records the most recent successful authentication time. This is
// best-effort: a failure here does not invalidate the request.
func (s *SQLite) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE api_keys SET last_used_at = ? WHERE id = ?",
		at.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("%w: touch api key: %w", ErrStore, err)
	}
	return nil
}

// scanAPIKeyRow decodes a *sql.Row into an APIKeyRecord.
func scanAPIKeyRow(row *sql.Row) (*APIKeyRecord, error) {
	var rec APIKeyRecord
	var scopeJSON, created string
	var expires, lastUsed, revoked, createdBy sql.NullString
	if err := row.Scan(&rec.ID, &rec.TokenHash, &rec.Name, &rec.Role, &scopeJSON,
		&created, &expires, &lastUsed, &revoked, &createdBy); err != nil {
		return nil, err
	}
	if err := finishAPIKey(&rec, scopeJSON, created, expires, lastUsed, revoked, createdBy); err != nil {
		return nil, err
	}
	return &rec, nil
}

// scanAPIKeyRows decodes the current row of a *sql.Rows cursor into an APIKeyRecord.
func scanAPIKeyRows(rows *sql.Rows) (*APIKeyRecord, error) {
	var rec APIKeyRecord
	var scopeJSON, created string
	var expires, lastUsed, revoked, createdBy sql.NullString
	if err := rows.Scan(&rec.ID, &rec.TokenHash, &rec.Name, &rec.Role, &scopeJSON,
		&created, &expires, &lastUsed, &revoked, &createdBy); err != nil {
		return nil, err
	}
	if err := finishAPIKey(&rec, scopeJSON, created, expires, lastUsed, revoked, createdBy); err != nil {
		return nil, err
	}
	return &rec, nil
}

// finishAPIKey populates the time and slice fields on an APIKeyRecord after the
// raw columns have been scanned. Centralises parsing so both row and rows
// helpers stay consistent.
func finishAPIKey(rec *APIKeyRecord, scopeJSON, created string, expires, lastUsed, revoked, createdBy sql.NullString) error {
	if err := json.Unmarshal([]byte(scopeJSON), &rec.ClusterScope); err != nil {
		return fmt.Errorf("%w: unmarshal scope: %w", ErrQuery, err)
	}
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return fmt.Errorf("%w: parse created_at: %w", ErrQuery, err)
	}
	rec.CreatedAt = t
	if expires.Valid && expires.String != "" {
		if t, err := time.Parse(time.RFC3339, expires.String); err == nil {
			rec.ExpiresAt = t
		}
	}
	if lastUsed.Valid && lastUsed.String != "" {
		if t, err := time.Parse(time.RFC3339, lastUsed.String); err == nil {
			rec.LastUsedAt = t
		}
	}
	if revoked.Valid && revoked.String != "" {
		if t, err := time.Parse(time.RFC3339, revoked.String); err == nil {
			rec.RevokedAt = t
		}
	}
	if createdBy.Valid {
		rec.CreatedBy = createdBy.String
	}
	return nil
}
