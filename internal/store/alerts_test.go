package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestAlertUpsertAndGet verifies an alert round-trips through UpsertAlert and
// GetAlert with every field preserved, and that reusing the fingerprint
// updates the existing row in place rather than inserting a duplicate.
func TestAlertUpsertAndGet(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	starts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	received := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	rec := AlertRecord{
		Fingerprint:  "fp1",
		Cluster:      "prod-east",
		Status:       "firing",
		AlertName:    "HighMemory",
		Severity:     "critical",
		Summary:      "memory above threshold",
		StartsAt:     starts,
		ReceivedAt:   received,
		Labels:       map[string]string{"cluster": "prod-east", "team": "core"},
		Annotations:  map[string]string{"summary": "memory above threshold"},
		GeneratorURL: "http://prometheus/graph",
	}
	if err := s.UpsertAlert(ctx, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetAlert(ctx, "fp1")
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if diff := cmp.Diff(rec.Labels, got.Labels, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("labels mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(rec.Annotations, got.Annotations, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("annotations mismatch (-want +got):\n%s", diff)
	}
	if got.Severity != "critical" || got.Summary != "memory above threshold" || got.GeneratorURL != "http://prometheus/graph" {
		t.Errorf("optional fields not preserved: %+v", got)
	}
	if !got.StartsAt.Equal(starts) || !got.ReceivedAt.Equal(received) {
		t.Errorf("timestamps not preserved: starts=%v received=%v", got.StartsAt, got.ReceivedAt)
	}

	// Transition firing -> resolved on the same fingerprint updates in place.
	rec.Status = "resolved"
	rec.EndsAt = time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC)
	if err := s.UpsertAlert(ctx, rec); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	list, err := s.ListAlerts(ctx, AlertListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if diff := cmp.Diff(1, len(list)); diff != "" {
		t.Errorf("upsert should keep one row (-want +got):\n%s", diff)
	}
	if list[0].Status != "resolved" || list[0].EndsAt.IsZero() {
		t.Errorf("update not applied: %+v", list[0])
	}
}

// TestUpsertAlertDefaults verifies a missing fingerprint is rejected and a zero
// ReceivedAt is defaulted to the current time.
func TestUpsertAlertDefaults(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	if err := s.UpsertAlert(ctx, AlertRecord{}); !errors.Is(err, ErrStore) {
		t.Errorf("empty fingerprint: want ErrStore, got %v", err)
	}

	if err := s.UpsertAlert(ctx, AlertRecord{Fingerprint: "fp", Cluster: "c", Status: "firing", AlertName: "n"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.GetAlert(ctx, "fp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ReceivedAt.IsZero() {
		t.Error("expected ReceivedAt to be defaulted to now")
	}
}

// TestGetAlertNotFound verifies a missing fingerprint returns ErrNotFound.
func TestGetAlertNotFound(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	if _, err := s.GetAlert(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// TestListAlertsFilters verifies each filter clause and the default limit.
func TestListAlertsFilters(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seed := []AlertRecord{
		{Fingerprint: "a", Cluster: "prod-east", Status: "firing", AlertName: "A", Severity: "critical", ReceivedAt: base.Add(-2 * time.Hour)},
		{Fingerprint: "b", Cluster: "prod-west", Status: "firing", AlertName: "B", Severity: "warning", ReceivedAt: base.Add(-1 * time.Hour)},
		{Fingerprint: "c", Cluster: "prod-east", Status: "resolved", AlertName: "C", Severity: "critical", ReceivedAt: base.Add(-30 * time.Minute)},
	}
	for _, r := range seed {
		if err := s.UpsertAlert(ctx, r); err != nil {
			t.Fatalf("seed %s: %v", r.Fingerprint, err)
		}
	}

	tests := []struct {
		Name     string
		Opts     AlertListOptions
		WantRows int
	}{{ // Test 0: No filters returns every alert.
		Name: "no filters", Opts: AlertListOptions{}, WantRows: 3,
	}, { // Test 1: Cluster filter restricts to one cluster.
		Name: "cluster", Opts: AlertListOptions{Cluster: "prod-east"}, WantRows: 2,
	}, { // Test 2: Status filter restricts to firing.
		Name: "status", Opts: AlertListOptions{Status: "firing"}, WantRows: 2,
	}, { // Test 3: Severity filter restricts to warning.
		Name: "severity", Opts: AlertListOptions{Severity: "warning"}, WantRows: 1,
	}, { // Test 4: Since excludes alerts received at or before the cutoff.
		Name: "since", Opts: AlertListOptions{Since: base.Add(-90 * time.Minute)}, WantRows: 2,
	}, { // Test 5: Limit caps the row count, newest first.
		Name: "limit", Opts: AlertListOptions{Limit: 1}, WantRows: 1,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := s.ListAlerts(ctx, test.Opts)
			if err != nil {
				t.Fatalf("test %d: list: %v", i, err)
			}
			if diff := cmp.Diff(test.WantRows, len(got)); diff != "" {
				t.Errorf("test %d: row count (-want +got):\n%s", i, diff)
			}
		})
	}
}

// TestListAlertsOrderingAndLimit verifies newest received_at first ordering.
func TestListAlertsOrderingAndLimit(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	_ = s.UpsertAlert(ctx, AlertRecord{Fingerprint: "old", Cluster: "c", Status: "firing", AlertName: "old", ReceivedAt: base.Add(-time.Hour)})
	_ = s.UpsertAlert(ctx, AlertRecord{Fingerprint: "new", Cluster: "c", Status: "firing", AlertName: "new", ReceivedAt: base})

	got, err := s.ListAlerts(ctx, AlertListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].Fingerprint != "new" {
		t.Errorf("expected newest first; got %+v", got)
	}
}

// TestPruneAlerts verifies rows older than the cutoff are removed and newer
// rows are retained.
func TestPruneAlerts(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_ = s.UpsertAlert(ctx, AlertRecord{Fingerprint: "stale", Cluster: "c", Status: "resolved", AlertName: "s", ReceivedAt: base.Add(-48 * time.Hour)})
	_ = s.UpsertAlert(ctx, AlertRecord{Fingerprint: "fresh", Cluster: "c", Status: "firing", AlertName: "f", ReceivedAt: base})

	n, err := s.PruneAlerts(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if diff := cmp.Diff(1, n); diff != "" {
		t.Errorf("pruned count (-want +got):\n%s", diff)
	}
	remaining, _ := s.ListAlerts(ctx, AlertListOptions{})
	if len(remaining) != 1 || remaining[0].Fingerprint != "fresh" {
		t.Errorf("expected only fresh alert to remain; got %+v", remaining)
	}
}

// TestNullableTime verifies zero times become SQL NULL and non-zero times
// render as RFC3339Nano strings.
func TestNullableTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		In      time.Time
		WantStr string
		WantNil bool
	}{{ // Test 0: Zero time maps to nil (SQL NULL).
		Name: "zero", In: time.Time{}, WantNil: true,
	}, { // Test 1: Non-zero time maps to an RFC3339Nano string.
		Name: "set", In: time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC), WantStr: "2026-06-07T08:09:10Z",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := nullableTime(test.In)
			if test.WantNil {
				if got != nil {
					t.Errorf("test %d: want nil, got %v", i, got)
				}
				return
			}
			if diff := cmp.Diff(test.WantStr, got); diff != "" {
				t.Errorf("test %d: (-want +got):\n%s", i, diff)
			}
		})
	}
}
