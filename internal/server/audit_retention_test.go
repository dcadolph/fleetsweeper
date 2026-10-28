package server

import (
	"context"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestPruneAuditOnce verifies a single retention pass removes rows older than
// the cutoff while keeping newer ones.
func TestPruneAuditOnce(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if err := ss.SaveAuditEntry(ctx, store.AuditEntry{
		Method: "POST", Path: "/old", Status: 200, Timestamp: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := ss.SaveAuditEntry(ctx, store.AuditEntry{
		Method: "POST", Path: "/new", Status: 200, Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("seed new: %v", err)
	}

	srv.pruneAuditOnce(ctx, time.Hour)

	entries, err := ss.ListAuditEntries(ctx, store.AuditListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "/new" {
		t.Errorf("expected only the recent entry to survive, got %+v", entries)
	}
}

// TestStartAuditRetention covers the disabled guard and the immediate first
// prune performed by the launched goroutine.
func TestStartAuditRetention(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)

	// retain <= 0 is a no-op and must not launch anything.
	srv.StartAuditRetention(context.Background(), 0)

	if err := ss.SaveAuditEntry(context.Background(), store.AuditEntry{
		Method: "POST", Path: "/stale", Status: 200, Timestamp: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.StartAuditRetention(ctx, time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := ss.ListAuditEntries(context.Background(), store.AuditListOptions{})
		if len(entries) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected the stale entry to be pruned by the retention goroutine")
}
