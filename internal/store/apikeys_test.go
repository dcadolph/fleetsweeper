package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestAPIKeyRoundTrip verifies a key can be saved and looked up by hash.
func TestAPIKeyRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	raw, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	rec := APIKeyRecord{
		ID:           "key_test_1",
		TokenHash:    HashToken(raw),
		Name:         "ci-runner",
		Role:         RoleOperator,
		ClusterScope: []string{"prod-east", "group:prod"},
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    "test",
	}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.GetAPIKeyByHash(ctx, rec.TokenHash)
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if diff := cmp.Diff(rec, *got, cmpopts.IgnoreFields(APIKeyRecord{}, "CreatedAt", "ExpiresAt", "LastUsedAt", "RevokedAt")); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
}

// TestAPIKeyValidation verifies the role and ID guards reject bad input.
func TestAPIKeyValidation(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	tests := []struct {
		Name string
		Rec  APIKeyRecord
	}{{
		Name: "Test 0: Missing ID rejected.",
		Rec:  APIKeyRecord{TokenHash: "abc", Role: RoleAdmin, Name: "x"},
	}, {
		Name: "Test 1: Missing token hash rejected.",
		Rec:  APIKeyRecord{ID: "k1", Role: RoleAdmin, Name: "x"},
	}, {
		Name: "Test 2: Invalid role rejected.",
		Rec:  APIKeyRecord{ID: "k1", TokenHash: "abc", Role: "godmode", Name: "x"},
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if err := s.SaveAPIKey(ctx, test.Rec); err == nil {
				t.Errorf("test %d: expected error, got nil", i)
			}
		})
	}
}

// TestAPIKeyDuplicateHash verifies the unique constraint on token_hash.
func TestAPIKeyDuplicateHash(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	rec := APIKeyRecord{
		ID:           "k1",
		TokenHash:    "deadbeef",
		Name:         "first",
		Role:         RoleViewer,
		ClusterScope: []string{ScopeWildcard},
	}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save first: %v", err)
	}
	rec.ID = "k2"
	rec.Name = "second"
	if err := s.SaveAPIKey(ctx, rec); err == nil {
		t.Error("expected duplicate-hash error, got nil")
	}
}

// TestAPIKeyRevoke verifies revocation marks the key disabled and is idempotent
// to "already revoked" via ErrNotFound.
func TestAPIKeyRevoke(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	rec := APIKeyRecord{
		ID:           "k_revoke",
		TokenHash:    "h_revoke",
		Name:         "tmp",
		Role:         RoleViewer,
		ClusterScope: []string{ScopeWildcard},
	}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.RevokeAPIKey(ctx, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := s.GetAPIKey(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RevokedAt.IsZero() {
		t.Error("expected RevokedAt to be set after revoke")
	}

	if err := s.RevokeAPIKey(ctx, rec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("re-revoke: want ErrNotFound, got %v", err)
	}
}

// TestAPIKeyTouch verifies LastUsedAt updates without error.
func TestAPIKeyTouch(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	rec := APIKeyRecord{
		ID:           "k_touch",
		TokenHash:    "h_touch",
		Name:         "x",
		Role:         RoleViewer,
		ClusterScope: []string{ScopeWildcard},
	}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	at := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if err := s.TouchAPIKey(ctx, rec.ID, at); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, err := s.GetAPIKey(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.LastUsedAt.Equal(at) {
		t.Errorf("LastUsedAt: want %v, got %v", at, got.LastUsedAt)
	}
}

// TestListAPIKeysIncludesRevoked verifies revoked keys are not hidden so
// administrators can audit them.
func TestListAPIKeysIncludesRevoked(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	keys := []APIKeyRecord{
		{ID: "a", TokenHash: "ha", Name: "a", Role: RoleAdmin, ClusterScope: []string{ScopeWildcard}},
		{ID: "b", TokenHash: "hb", Name: "b", Role: RoleViewer, ClusterScope: []string{ScopeWildcard}},
	}
	for _, k := range keys {
		if err := s.SaveAPIKey(ctx, k); err != nil {
			t.Fatalf("save %s: %v", k.ID, err)
		}
	}
	if err := s.RevokeAPIKey(ctx, "b"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := s.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 keys, got %d", len(got))
	}
}

// newTestSQLite opens an isolated SQLite database in a temporary directory.
func newTestSQLite(t *testing.T) *SQLite {
	t.Helper()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
