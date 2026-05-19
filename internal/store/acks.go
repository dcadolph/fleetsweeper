package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// AckRecord is a single finding acknowledgement persisted in SQLite.
// The fingerprint is stable across scans for the same finding shape
// (cluster + scanner + title) so a recurring critical can be acknowledged
// once instead of every scan cycle.
type AckRecord struct {
	// Fingerprint is the SHA-256 of cluster|scanner|title.
	Fingerprint string `json:"fingerprint"`
	// Cluster echoes the finding's cluster scope (or "fleet").
	Cluster string `json:"cluster"`
	// Scanner echoes the finding's source scanner.
	Scanner string `json:"scanner"`
	// Title echoes the finding's title at ack time, for human context.
	Title string `json:"title"`
	// AckBy identifies the operator who acked, free-form.
	AckBy string `json:"ack_by,omitempty"`
	// Reason is the operator's stated reason for acking.
	Reason string `json:"reason,omitempty"`
	// SnoozeUntil, when non-zero, is when the ack expires and the finding
	// resumes alerting. Zero value means "permanent until removed".
	SnoozeUntil time.Time `json:"snooze_until,omitempty"`
	// CreatedAt is when the ack was recorded.
	CreatedAt time.Time `json:"created_at"`
}

// AckFingerprint returns the stable SHA-256 used to key acknowledgements for
// a finding identified by its cluster, scanner, and title.
func AckFingerprint(cluster, scanner, title string) string {
	h := sha256.New()
	h.Write([]byte(cluster))
	h.Write([]byte{0})
	h.Write([]byte(scanner))
	h.Write([]byte{0})
	h.Write([]byte(title))
	return hex.EncodeToString(h.Sum(nil))
}

// SaveAck upserts an acknowledgement. The fingerprint is the primary key, so
// re-acking an already-acked finding refreshes its metadata in place.
func (s *SQLite) SaveAck(ctx context.Context, rec AckRecord) error {
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
	_, err := s.db.ExecContext(ctx, `
INSERT INTO finding_acks (fingerprint, cluster, scanner, title, ack_by, reason, snooze_until, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(fingerprint) DO UPDATE SET
    cluster      = excluded.cluster,
    scanner      = excluded.scanner,
    title        = excluded.title,
    ack_by       = excluded.ack_by,
    reason       = excluded.reason,
    snooze_until = excluded.snooze_until,
    created_at   = excluded.created_at`,
		rec.Fingerprint, rec.Cluster, rec.Scanner, rec.Title,
		rec.AckBy, rec.Reason, snoozeStr, rec.CreatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("%w: save ack: %w", ErrStore, err)
	}
	return nil
}

// DeleteAck removes an acknowledgement by fingerprint. Idempotent: a missing
// row is not an error so callers can call from a "clear" button without
// worrying about state.
func (s *SQLite) DeleteAck(ctx context.Context, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM finding_acks WHERE fingerprint = ?", fingerprint)
	if err != nil {
		return fmt.Errorf("%w: delete ack: %w", ErrStore, err)
	}
	return nil
}

// ListAcks returns every active ack. Expired snoozes are filtered out and
// removed from the database as a side effect so the table stays small.
func (s *SQLite) ListAcks(ctx context.Context) ([]AckRecord, error) {
	if err := s.pruneExpiredAcks(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
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

// IsAcked reports whether a finding identified by fingerprint has an active
// (non-expired) ack.
func (s *SQLite) IsAcked(ctx context.Context, fingerprint string) (bool, error) {
	if err := s.pruneExpiredAcks(ctx); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(1) FROM finding_acks WHERE fingerprint = ?", fingerprint,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("%w: is acked: %w", ErrStore, err)
	}
	return n > 0, nil
}

// pruneExpiredAcks deletes acks whose snooze has elapsed.
func (s *SQLite) pruneExpiredAcks(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM finding_acks WHERE snooze_until IS NOT NULL AND snooze_until != '' AND snooze_until < ?",
		now)
	if err != nil {
		return fmt.Errorf("%w: prune expired acks: %w", ErrStore, err)
	}
	return nil
}

// scanAckRow decodes one row of finding_acks into an AckRecord.
func scanAckRow(rows *sql.Rows) (AckRecord, error) {
	var r AckRecord
	var snooze sql.NullString
	var created string
	if err := rows.Scan(&r.Fingerprint, &r.Cluster, &r.Scanner, &r.Title,
		&r.AckBy, &r.Reason, &snooze, &created); err != nil {
		return r, fmt.Errorf("%w: scan ack row: %w", ErrStore, err)
	}
	if snooze.Valid && snooze.String != "" {
		t, err := time.Parse(time.RFC3339, snooze.String)
		if err == nil {
			r.SnoozeUntil = t
		}
	}
	t, err := time.Parse(time.RFC3339, created)
	if err == nil {
		r.CreatedAt = t
	}
	return r, nil
}
