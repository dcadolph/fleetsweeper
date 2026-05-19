package store

import (
	"context"
	"testing"
	"time"
)

// TestAuditRoundTrip verifies a saved entry comes back with key fields intact.
func TestAuditRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	rec := AuditEntry{
		ActorID:    "key_test",
		ActorName:  "ci-runner",
		ActorRole:  RoleOperator,
		Method:     "POST",
		Path:       "/scans",
		Status:     202,
		RemoteAddr: "10.1.2.3:50001",
		UserAgent:  "fleetsweeper-cli/1.0",
		DurationMS: 42,
	}
	if err := s.SaveAuditEntry(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.ListAuditEntries(ctx, AuditListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].ActorID != rec.ActorID || got[0].Path != rec.Path || got[0].Status != rec.Status {
		t.Errorf("fields not preserved: %+v", got[0])
	}
}

// TestAuditFilters verifies the Since, ActorID, and MinStatus filters.
func TestAuditFilters(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	now := time.Now().UTC()
	entries := []AuditEntry{
		{ActorID: "a", Method: "POST", Path: "/scans", Status: 202, Timestamp: now.Add(-2 * time.Hour)},
		{ActorID: "b", Method: "POST", Path: "/scans", Status: 403, Timestamp: now.Add(-1 * time.Hour)},
		{ActorID: "a", Method: "DELETE", Path: "/groups/x", Status: 500, Timestamp: now.Add(-30 * time.Minute)},
	}
	for _, e := range entries {
		if err := s.SaveAuditEntry(ctx, e); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	tests := []struct {
		Name     string
		Opts     AuditListOptions
		WantRows int
	}{{
		Name:     "Test 0: No filters returns all.",
		Opts:     AuditListOptions{},
		WantRows: 3,
	}, {
		Name:     "Test 1: ActorID filter returns only that actor.",
		Opts:     AuditListOptions{ActorID: "a"},
		WantRows: 2,
	}, {
		Name:     "Test 2: MinStatus 400 returns only failures.",
		Opts:     AuditListOptions{MinStatus: 400},
		WantRows: 2,
	}, {
		Name:     "Test 3: Since filter excludes older entries.",
		Opts:     AuditListOptions{Since: now.Add(-90 * time.Minute)},
		WantRows: 2,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := s.ListAuditEntries(ctx, test.Opts)
			if err != nil {
				t.Fatalf("test %d: list: %v", i, err)
			}
			if len(got) != test.WantRows {
				t.Errorf("test %d: want %d rows, got %d", i, test.WantRows, len(got))
			}
		})
	}
}

// TestAuditOrdering verifies entries come back newest-first.
func TestAuditOrdering(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := s.SaveAuditEntry(ctx, AuditEntry{
		Method: "POST", Path: "/old", Status: 200,
		Timestamp: now.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("save old: %v", err)
	}
	if err := s.SaveAuditEntry(ctx, AuditEntry{
		Method: "POST", Path: "/new", Status: 200,
		Timestamp: now,
	}); err != nil {
		t.Fatalf("save new: %v", err)
	}
	got, err := s.ListAuditEntries(ctx, AuditListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].Path != "/new" {
		t.Errorf("expected /new first; got %+v", got)
	}
}
