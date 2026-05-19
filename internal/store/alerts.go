package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AlertRecord is one inbound AlertManager alert persisted to the alerts
// table. Fingerprint is AlertManager's stable per-alert identifier and is
// reused as the primary key so a transition from firing to resolved
// updates the existing row in place.
type AlertRecord struct {
	// Fingerprint is the AlertManager-assigned stable identity.
	Fingerprint string `json:"fingerprint"`
	// Cluster is the cluster the alert applies to. Derived from the
	// `cluster` label when present and falling back to the empty string
	// when AlertManager doesn't carry a cluster label.
	Cluster string `json:"cluster"`
	// Status is "firing" or "resolved".
	Status string `json:"status"`
	// AlertName is the value of the alertname label.
	AlertName string `json:"alertname"`
	// Severity is the value of the severity label when present.
	Severity string `json:"severity,omitempty"`
	// Summary is the value of the summary annotation when present.
	Summary string `json:"summary,omitempty"`
	// StartsAt is when the alert began firing.
	StartsAt time.Time `json:"starts_at,omitempty"`
	// EndsAt is when the alert resolved (zero while firing).
	EndsAt time.Time `json:"ends_at,omitempty"`
	// ReceivedAt is when Fleetsweeper recorded the alert.
	ReceivedAt time.Time `json:"received_at"`
	// Labels carries every label AlertManager attached to the alert.
	Labels map[string]string `json:"labels"`
	// Annotations carries every annotation AlertManager attached to the alert.
	Annotations map[string]string `json:"annotations"`
	// GeneratorURL is the link back to the Prometheus rule that fired.
	GeneratorURL string `json:"generator_url,omitempty"`
}

// AlertListOptions filters AlertRecord queries.
type AlertListOptions struct {
	// Limit caps the number of rows returned. Defaults to 200 when zero.
	Limit int
	// Cluster, when non-empty, restricts results to a single cluster.
	Cluster string
	// Status, when non-empty, filters by alert status ("firing"/"resolved").
	Status string
	// Severity, when non-empty, filters by severity label value.
	Severity string
	// Since, when non-zero, only returns alerts received strictly after this time.
	Since time.Time
}

// UpsertAlert inserts or updates an alert keyed by fingerprint.
func (s *SQLite) UpsertAlert(ctx context.Context, rec AlertRecord) error {
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
	_, err = s.db.ExecContext(ctx, `
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
func (s *SQLite) GetAlert(ctx context.Context, fingerprint string) (*AlertRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
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
func (s *SQLite) ListAlerts(ctx context.Context, opts AlertListOptions) ([]AlertRecord, error) {
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
	rows, err := s.db.QueryContext(ctx, `
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

// PruneAlerts removes alert rows older than cutoff. Returns rows removed.
func (s *SQLite) PruneAlerts(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM alerts WHERE received_at < ?",
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("%w: prune alerts: %w", ErrStore, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// scanAlertRow decodes a single alerts row into an AlertRecord.
func scanAlertRow(rows *sql.Rows) (AlertRecord, error) {
	var r AlertRecord
	var severity, summary, generatorURL sql.NullString
	var startsAt, endsAt sql.NullString
	var receivedAt, labelsJSON, annJSON string
	if err := rows.Scan(&r.Fingerprint, &r.Cluster, &r.Status, &r.AlertName,
		&severity, &summary, &startsAt, &endsAt, &receivedAt,
		&labelsJSON, &annJSON, &generatorURL); err != nil {
		return r, fmt.Errorf("%w: scan alert row: %w", ErrQuery, err)
	}
	r.Severity = severity.String
	r.Summary = summary.String
	r.GeneratorURL = generatorURL.String
	if t, err := time.Parse(time.RFC3339Nano, receivedAt); err == nil {
		r.ReceivedAt = t
	}
	if startsAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, startsAt.String); err == nil {
			r.StartsAt = t
		}
	}
	if endsAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, endsAt.String); err == nil {
			r.EndsAt = t
		}
	}
	if err := json.Unmarshal([]byte(labelsJSON), &r.Labels); err != nil {
		return r, fmt.Errorf("%w: decode labels: %w", ErrQuery, err)
	}
	if err := json.Unmarshal([]byte(annJSON), &r.Annotations); err != nil {
		return r, fmt.Errorf("%w: decode annotations: %w", ErrQuery, err)
	}
	return r, nil
}

// nullableTime converts a zero Time to SQL NULL.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
