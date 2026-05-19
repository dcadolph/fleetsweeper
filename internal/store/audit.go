package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// AuditEntry is a single audit log row recording one mutating request.
// Read-only requests are not audited to keep the table volume manageable;
// the request log already captures those at info level.
type AuditEntry struct {
	// ID is a time-sortable identifier.
	ID string `json:"id"`
	// Timestamp is when the request was received.
	Timestamp time.Time `json:"timestamp"`
	// ActorID identifies the api key that performed the action.
	// Empty when --insecure mode allowed an anonymous call.
	ActorID string `json:"actor_id,omitempty"`
	// ActorName is the key's human-readable label at request time.
	ActorName string `json:"actor_name,omitempty"`
	// ActorRole is the role the key carried at request time.
	ActorRole string `json:"actor_role,omitempty"`
	// Method is the HTTP verb (POST, PUT, DELETE).
	Method string `json:"method"`
	// Path is the request path.
	Path string `json:"path"`
	// Status is the HTTP response status.
	Status int `json:"status"`
	// RemoteAddr is the client address as reported by the transport.
	RemoteAddr string `json:"remote_addr,omitempty"`
	// UserAgent is the client's User-Agent header.
	UserAgent string `json:"user_agent,omitempty"`
	// DurationMS is the request handler duration in milliseconds.
	DurationMS int64 `json:"duration_ms"`
	// Error, when non-empty, is a short message describing why the request
	// failed authorisation or processing.
	Error string `json:"error,omitempty"`
}

// AuditListOptions filters AuditEntry queries.
type AuditListOptions struct {
	// Limit caps the number of rows returned. Defaults to 100 when zero.
	Limit int
	// Since, when non-zero, only returns entries strictly newer than this time.
	Since time.Time
	// ActorID, when non-empty, restricts results to a single API key.
	ActorID string
	// MinStatus, when non-zero, only returns entries with status >= MinStatus.
	// Use 400 to surface only failures.
	MinStatus int
}

// SaveAuditEntry inserts one audit entry. ID and Timestamp default to fresh
// values when unset, so callers can supply just the request-level fields.
func (s *SQLite) SaveAuditEntry(ctx context.Context, rec AuditEntry) error {
	if rec.ID == "" {
		rec.ID = generateID()
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
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
func (s *SQLite) PruneAuditEntries(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM audit_log WHERE timestamp < ?",
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("%w: prune audit: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListAuditEntries returns audit entries matching opts, newest first.
func (s *SQLite) ListAuditEntries(ctx context.Context, opts AuditListOptions) ([]AuditEntry, error) {
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
	rows, err := s.db.QueryContext(ctx, `
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

// scanAuditRow decodes a single audit_log row into an AuditEntry.
func scanAuditRow(rows *sql.Rows) (AuditEntry, error) {
	var r AuditEntry
	var ts string
	var actorID, actorName, actorRole, remoteAddr, userAgent, errMsg sql.NullString
	if err := rows.Scan(&r.ID, &ts, &actorID, &actorName, &actorRole,
		&r.Method, &r.Path, &r.Status,
		&remoteAddr, &userAgent, &r.DurationMS, &errMsg); err != nil {
		return r, fmt.Errorf("%w: scan audit row: %w", ErrQuery, err)
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		r.Timestamp = t
	}
	r.ActorID = actorID.String
	r.ActorName = actorName.String
	r.ActorRole = actorRole.String
	r.RemoteAddr = remoteAddr.String
	r.UserAgent = userAgent.String
	r.Error = errMsg.String
	return r, nil
}

// nullable converts an empty string into a SQL NULL so the column can be
// indexed without storing empty strings.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
