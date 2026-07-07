package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestHandleAdminRevokeKey_Happy verifies revoking a stored key marks it
// revoked and returns 204.
func TestHandleAdminRevokeKey_Happy(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)
	raw, _ := store.GenerateToken()
	rec := store.APIKeyRecord{
		ID: "key_revoke_me", TokenHash: store.HashToken(raw),
		Name: "temp", Role: store.RoleViewer, ClusterScope: []string{store.ScopeWildcard},
	}
	if err := st.SaveAPIKey(context.Background(), rec); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/keys/key_revoke_me", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", w.Code, w.Body.String())
	}
	got, err := st.GetAPIKey(context.Background(), "key_revoke_me")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if got.RevokedAt.IsZero() {
		t.Error("expected key to be revoked")
	}
}

// TestHandleAdminRevokeKey_Unknown verifies an unknown key ID 404s.
func TestHandleAdminRevokeKey_Unknown(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/keys/nope", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleAdminRevokeKey_EmptyID verifies a missing path value 400s.
func TestHandleAdminRevokeKey_EmptyID(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/keys/", nil)
	req.SetPathValue("id", "")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleAdminRevokeKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// seedAuditEntries writes a handful of audit rows spanning two actors and
// mixed statuses so the list filters can be exercised.
func seedAuditEntries(t *testing.T, st *store.SQLite) {
	t.Helper()
	rows := []store.AuditEntry{
		{ActorID: "alice", Method: "POST", Path: "/groups", Status: 201, Timestamp: time.Now().Add(-3 * time.Minute)},
		{ActorID: "alice", Method: "DELETE", Path: "/groups/x", Status: 403, Timestamp: time.Now().Add(-2 * time.Minute)},
		{ActorID: "bob", Method: "PUT", Path: "/locations/x", Status: 500, Timestamp: time.Now().Add(-1 * time.Minute)},
	}
	for _, r := range rows {
		if err := st.SaveAuditEntry(context.Background(), r); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
}

// TestHandleAdminListAudit_Filters covers the audit list query parameters:
// unfiltered, actor filter, and min-status filter.
func TestHandleAdminListAudit_Filters(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)
	seedAuditEntries(t, st)

	tests := []struct {
		Name      string
		Query     string
		WantCount int
	}{{ // Test 0: No filter returns all seeded rows.
		Name: "all", Query: "", WantCount: 3,
	}, { // Test 1: Actor filter restricts to alice.
		Name: "actor", Query: "?actor=alice", WantCount: 2,
	}, { // Test 2: min_status=400 surfaces only failures.
		Name: "min status", Query: "?min_status=400", WantCount: 2,
	}, { // Test 3: limit caps rows returned.
		Name: "limit", Query: "?limit=1", WantCount: 1,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/admin/audit"+test.Query, nil)
			req.Header.Set("Authorization", "Bearer bootstrap-secret")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
			}
			var entries []store.AuditEntry
			if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(entries) != test.WantCount {
				t.Errorf("%s: want %d entries, got %d", test.Name, test.WantCount, len(entries))
			}
		})
	}
}
