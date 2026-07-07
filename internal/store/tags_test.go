package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestClusterTagSetGetDelete verifies the tag lifecycle: set several tags,
// upsert one in place, read them back, and delete one.
func TestClusterTagSetGetDelete(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	if err := s.SetClusterTag(ctx, "prod-east", "env", "prod"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := s.SetClusterTag(ctx, "prod-east", "tier", "critical"); err != nil {
		t.Fatalf("set tier: %v", err)
	}

	got, err := s.GetClusterTags(ctx, "prod-east")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	want := map[string]string{"env": "prod", "tier": "critical"}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("tags mismatch (-want +got):\n%s", diff)
	}

	// Upsert the same key updates the value in place.
	if err := s.SetClusterTag(ctx, "prod-east", "tier", "standard"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	got, _ = s.GetClusterTags(ctx, "prod-east")
	if got["tier"] != "standard" {
		t.Errorf("upsert did not overwrite: %+v", got)
	}

	// Delete one key.
	if err := s.DeleteClusterTag(ctx, "prod-east", "env"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ = s.GetClusterTags(ctx, "prod-east")
	if diff := cmp.Diff(map[string]string{"tier": "standard"}, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("after delete (-want +got):\n%s", diff)
	}
}

// TestSetClusterTagValidation verifies empty cluster or key inputs are rejected.
func TestSetClusterTagValidation(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	tests := []struct {
		Name    string
		Cluster string
		Key     string
	}{{ // Test 0: Empty cluster rejected.
		Name: "empty cluster", Cluster: "", Key: "env",
	}, { // Test 1: Empty key rejected.
		Name: "empty key", Cluster: "prod", Key: "",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if err := s.SetClusterTag(ctx, test.Cluster, test.Key, "v"); !errors.Is(err, ErrStore) {
				t.Errorf("test %d: want ErrStore, got %v", i, err)
			}
		})
	}
}

// TestDeleteClusterTagIdempotent verifies deleting a missing tag is not an error.
func TestDeleteClusterTagIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	if err := s.DeleteClusterTag(context.Background(), "prod", "missing"); err != nil {
		t.Errorf("delete missing tag: want nil, got %v", err)
	}
}

// TestGetClusterTagsEmpty verifies a cluster with no tags returns an empty map.
func TestGetClusterTagsEmpty(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	got, err := s.GetClusterTags(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if diff := cmp.Diff(map[string]string{}, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("expected empty map (-want +got):\n%s", diff)
	}
}

// TestListClusterTags verifies every tag across the fleet comes back grouped by
// cluster.
func TestListClusterTags(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	_ = s.SetClusterTag(ctx, "prod-east", "env", "prod")
	_ = s.SetClusterTag(ctx, "prod-east", "tier", "critical")
	_ = s.SetClusterTag(ctx, "dev-local", "env", "dev")

	got, err := s.ListClusterTags(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]map[string]string{
		"prod-east": {"env": "prod", "tier": "critical"},
		"dev-local": {"env": "dev"},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("grouped tags (-want +got):\n%s", diff)
	}
}
