package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdminSystemReturnsFeatures verifies the system endpoint serializes a
// reasonable snapshot of the running server.
func TestAdminSystemReturnsFeatures(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/system", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin/system: want 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp systemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Version == "" {
		t.Error("Version not populated")
	}
	if resp.GoVersion == "" {
		t.Error("GoVersion not populated")
	}
	if resp.Storage.Driver == "" {
		t.Error("Storage.Driver not populated")
	}
	if !resp.Storage.Healthy {
		t.Error("expected store to be healthy in test fixture")
	}
}

// TestAdminSystemGuardedByAdmin verifies non-admin actors are rejected.
func TestAdminSystemGuardedByAdmin(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/system", nil) // no auth header
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 without admin token, got %d", w.Code)
	}
}
