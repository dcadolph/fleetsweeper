package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestTokensEqual verifies the constant-time token comparison.
func TestTokensEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name   string
		A      string
		B      string
		WantEq bool
	}{{ // Test 0: Identical tokens compare equal.
		Name: "equal", A: "fsk_abc", B: "fsk_abc", WantEq: true,
	}, { // Test 1: Different tokens of equal length compare unequal.
		Name: "different", A: "fsk_abc", B: "fsk_xyz", WantEq: false,
	}, { // Test 2: Different lengths compare unequal.
		Name: "length", A: "fsk_abc", B: "fsk_abcd", WantEq: false,
	}, { // Test 3: Two empty strings compare equal.
		Name: "empty", A: "", B: "", WantEq: true,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := TokensEqual(test.A, test.B); got != test.WantEq {
				t.Errorf("test %d: want %v, got %v", i, test.WantEq, got)
			}
		})
	}
}

// TestValidRole verifies role validation accepts the three known roles and
// rejects anything else.
func TestValidRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Role string
		Want bool
	}{{ // Test 0: admin is valid.
		Name: "admin", Role: RoleAdmin, Want: true,
	}, { // Test 1: operator is valid.
		Name: "operator", Role: RoleOperator, Want: true,
	}, { // Test 2: viewer is valid.
		Name: "viewer", Role: RoleViewer, Want: true,
	}, { // Test 3: Empty role is invalid.
		Name: "empty", Role: "", Want: false,
	}, { // Test 4: Unknown role is invalid.
		Name: "unknown", Role: "root", Want: false,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := ValidRole(test.Role); got != test.Want {
				t.Errorf("test %d: want %v, got %v", i, test.Want, got)
			}
		})
	}
}

// TestHashToken verifies hashing is deterministic, sensitive to input, and
// produces a 64-character hex digest.
func TestHashToken(t *testing.T) {
	t.Parallel()
	h := HashToken("fsk_secret")
	if h != HashToken("fsk_secret") {
		t.Error("hash not deterministic for identical input")
	}
	if h == HashToken("fsk_other") {
		t.Error("hash collided across distinct inputs")
	}
	if len(h) != 64 {
		t.Errorf("want 64-char hex digest, got %d", len(h))
	}
}

// TestGenerateToken verifies fresh tokens are unique and carry the fsk_ prefix.
func TestGenerateToken(t *testing.T) {
	t.Parallel()
	a, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if a == b {
		t.Error("expected distinct tokens")
	}
	if !strings.HasPrefix(a, "fsk_") {
		t.Errorf("missing fsk_ prefix: %q", a)
	}
}

// TestGetAPIKeyNotFound verifies both lookups return ErrNotFound for a missing
// key.
func TestGetAPIKeyNotFound(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	if _, err := s.GetAPIKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAPIKey: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetAPIKeyByHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAPIKeyByHash: want ErrNotFound, got %v", err)
	}
}

// TestAPIKeyTimeFieldsRoundTrip verifies the optional expiry, last-used, and
// revoked timestamps survive a save/get round-trip.
func TestAPIKeyTimeFieldsRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	revoked := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	rec := APIKeyRecord{
		ID:           "k_times",
		TokenHash:    "h_times",
		Name:         "with-times",
		Role:         RoleOperator,
		ClusterScope: []string{"group:prod"},
		CreatedAt:    created,
		ExpiresAt:    expires,
		LastUsedAt:   lastUsed,
		RevokedAt:    revoked,
		CreatedBy:    "admin-key",
	}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.GetAPIKey(ctx, "k_times")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.CreatedAt.Equal(created) || !got.ExpiresAt.Equal(expires) ||
		!got.LastUsedAt.Equal(lastUsed) || !got.RevokedAt.Equal(revoked) {
		t.Errorf("time fields not preserved: %+v", got)
	}
	if got.CreatedBy != "admin-key" {
		t.Errorf("created_by not preserved: %q", got.CreatedBy)
	}
	if diff := cmp.Diff([]string{"group:prod"}, got.ClusterScope); diff != "" {
		t.Errorf("scope mismatch (-want +got):\n%s", diff)
	}
}

// TestSaveAPIKeyDefaultScope verifies an empty cluster scope defaults to the
// wildcard.
func TestSaveAPIKeyDefaultScope(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	rec := APIKeyRecord{ID: "k_scope", TokenHash: "h_scope", Name: "x", Role: RoleViewer}
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.GetAPIKey(ctx, "k_scope")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if diff := cmp.Diff([]string{ScopeWildcard}, got.ClusterScope); diff != "" {
		t.Errorf("default scope (-want +got):\n%s", diff)
	}
}
