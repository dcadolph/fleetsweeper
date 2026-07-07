package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestPruneAuditEntries verifies audit rows older than the cutoff are deleted
// while newer rows are retained.
func TestPruneAuditEntries(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	entries := []AuditEntry{
		{Method: "POST", Path: "/old", Status: 200, Timestamp: now.Add(-48 * time.Hour)},
		{Method: "POST", Path: "/new", Status: 200, Timestamp: now},
	}
	for _, e := range entries {
		if err := s.SaveAuditEntry(ctx, e); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	n, err := s.PruneAuditEntries(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if diff := cmp.Diff(1, n); diff != "" {
		t.Errorf("pruned count (-want +got):\n%s", diff)
	}
	got, err := s.ListAuditEntries(ctx, AuditListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Path != "/new" {
		t.Errorf("expected only the new entry to remain; got %+v", got)
	}
}

// TestSaveAuditEntryPresetID verifies a caller-supplied ID and timestamp are
// preserved rather than overwritten with generated defaults.
func TestSaveAuditEntryPresetID(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	ts := time.Date(2026, 4, 4, 4, 4, 4, 0, time.UTC)
	rec := AuditEntry{
		ID:        "fixed-id",
		Timestamp: ts,
		Method:    "DELETE",
		Path:      "/groups/x",
		Status:    204,
	}
	if err := s.SaveAuditEntry(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.ListAuditEntries(ctx, AuditListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].ID != "fixed-id" || !got[0].Timestamp.Equal(ts) {
		t.Errorf("preset id/timestamp not preserved: %+v", got[0])
	}
}
