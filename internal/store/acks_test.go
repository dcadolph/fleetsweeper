package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAckFingerprint_Stable(t *testing.T) {
	t.Parallel()
	a := AckFingerprint("c", "s", "t")
	b := AckFingerprint("c", "s", "t")
	if a != b {
		t.Errorf("fingerprint not stable for identical inputs")
	}
	if a == AckFingerprint("x", "s", "t") {
		t.Errorf("fingerprint collided across clusters")
	}
}

func TestSaveAndListAck(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	fp := AckFingerprint("prod-east", "node-health", "node down")
	err := s.SaveAck(ctx, AckRecord{
		Fingerprint: fp,
		Cluster:     "prod-east",
		Scanner:     "node-health",
		Title:       "node down",
		AckBy:       "alice",
		Reason:      "expected: hardware refresh in progress",
	})
	if err != nil {
		t.Fatalf("SaveAck: %v", err)
	}
	list, err := s.ListAcks(ctx)
	if err != nil {
		t.Fatalf("ListAcks: %v", err)
	}
	if len(list) != 1 || list[0].Fingerprint != fp {
		t.Errorf("expected one ack with fingerprint %s; got %+v", fp, list)
	}
	acked, err := s.IsAcked(ctx, fp)
	if err != nil || !acked {
		t.Errorf("IsAcked: want true, got %v (err=%v)", acked, err)
	}
}

func TestAck_Upsert(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	fp := AckFingerprint("c", "s", "t")
	_ = s.SaveAck(ctx, AckRecord{Fingerprint: fp, AckBy: "alice", Reason: "first"})
	_ = s.SaveAck(ctx, AckRecord{Fingerprint: fp, AckBy: "bob", Reason: "second"})
	list, _ := s.ListAcks(ctx)
	if len(list) != 1 {
		t.Fatalf("upsert should keep one row; got %d", len(list))
	}
	if list[0].AckBy != "bob" || list[0].Reason != "second" {
		t.Errorf("upsert did not overwrite: %+v", list[0])
	}
}

func TestDeleteAck_Idempotent(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.DeleteAck(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteAck on missing row: want nil, got %v", err)
	}
}

func TestSnooze_ExpiresAndIsPruned(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	fp := AckFingerprint("c", "s", "t")
	_ = s.SaveAck(ctx, AckRecord{
		Fingerprint: fp,
		SnoozeUntil: time.Now().Add(-time.Hour), // already expired
	})
	list, err := s.ListAcks(ctx)
	if err != nil {
		t.Fatalf("ListAcks: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expired snooze should be pruned; got %+v", list)
	}
	acked, _ := s.IsAcked(ctx, fp)
	if acked {
		t.Errorf("expired snooze should report not acked")
	}
}

// openTestStore creates a fresh SQLite store in a t.TempDir for one test.
func openTestStore(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acks.db")
	s, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
