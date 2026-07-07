package store

import (
	"context"
	"testing"
	"time"
)

// TestSaveAckEmptyFingerprint verifies an ack with no fingerprint is rejected.
func TestSaveAckEmptyFingerprint(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	if err := s.SaveAck(context.Background(), AckRecord{AckBy: "alice"}); err == nil {
		t.Error("expected an error for empty fingerprint")
	}
}

// TestAckSnoozeRoundTrip verifies a future snooze survives a save/list
// round-trip and keeps the finding acknowledged.
func TestAckSnoozeRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	fp := AckFingerprint("prod-east", "node-health", "disk pressure")
	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	if err := s.SaveAck(ctx, AckRecord{
		Fingerprint: fp,
		Cluster:     "prod-east",
		Scanner:     "node-health",
		Title:       "disk pressure",
		AckBy:       "bob",
		Reason:      "maintenance window",
		SnoozeUntil: until,
	}); err != nil {
		t.Fatalf("save ack: %v", err)
	}

	list, err := s.ListAcks(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 ack, got %d", len(list))
	}
	if !list[0].SnoozeUntil.Equal(until) {
		t.Errorf("snooze not preserved: want %v, got %v", until, list[0].SnoozeUntil)
	}
	acked, err := s.IsAcked(ctx, fp)
	if err != nil || !acked {
		t.Errorf("IsAcked: want true, got %v (err=%v)", acked, err)
	}
}

// TestIsAckedUnknown verifies an unknown fingerprint reports not acknowledged.
func TestIsAckedUnknown(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	acked, err := s.IsAcked(context.Background(), "no-such-fingerprint")
	if err != nil {
		t.Fatalf("is acked: %v", err)
	}
	if acked {
		t.Error("expected not acked for unknown fingerprint")
	}
}

// TestDeleteAckRemovesExisting verifies deleting an existing ack clears it.
func TestDeleteAckRemovesExisting(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	fp := AckFingerprint("c", "s", "t")
	if err := s.SaveAck(ctx, AckRecord{Fingerprint: fp, AckBy: "alice"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.DeleteAck(ctx, fp); err != nil {
		t.Fatalf("delete: %v", err)
	}
	acked, _ := s.IsAcked(ctx, fp)
	if acked {
		t.Error("expected not acked after delete")
	}
}
