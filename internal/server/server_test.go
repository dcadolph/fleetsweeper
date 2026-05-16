package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// testServer creates a Server backed by a temp SQLite database.
func testServer(t *testing.T) (*Server, *store.SQLite) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	registry := scanner.NewRegistry()
	srv := New(Config{
		Store:    s,
		Registry: registry,
		Log:      zap.NewNop(),
		Workers:  2,
		Insecure: true,
	})
	return srv, s
}

// TestBearerAuth verifies that mutating endpoints reject requests when an auth
// token is configured but the request lacks a matching bearer header, and
// accept requests that carry the correct token.
func TestBearerAuth(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	srv := New(Config{
		Store:     s,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "secret-token",
	})

	body := `{"name":"prod","clusters":["a","b"]}`

	noAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, noAuth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: want 401, got %d", w.Code)
	}

	wrongAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	wrongAuth.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, wrongAuth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", w.Code)
	}

	rightAuth := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	rightAuth.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, rightAuth)
	if w.Code != http.StatusCreated {
		t.Fatalf("right token: want 201, got %d body %s", w.Code, w.Body.String())
	}

	// GET should always pass when no Authorization header is supplied.
	read := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, read)
	if w.Code != http.StatusOK {
		t.Fatalf("read without token: want 200, got %d", w.Code)
	}
}

// TestHealthz confirms the liveness probe endpoint is unauthenticated and OK.
func TestHealthz(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: status %d", w.Code)
	}
}

func TestListScansEmpty(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if diff := cmp.Diff(http.StatusOK, w.Code); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}

	var scans []any
	json.Unmarshal(w.Body.Bytes(), &scans)
	if scans != nil && len(scans) != 0 {
		t.Errorf("expected empty list, got %d", len(scans))
	}
}

func TestScanRoundTrip(t *testing.T) {
	t.Parallel()
	srv, s := testServer(t)

	// Save a scan directly to the store.
	results := map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
	scanID, err := s.SaveScan(context.Background(), []string{"cluster-a"}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	// List scans via API.
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list scans: status %d", w.Code)
	}

	// Get scan report via API.
	req = httptest.NewRequest(http.MethodGet, "/api/scans/"+scanID+"/report", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get report: status %d, body: %s", w.Code, w.Body.String())
	}

	var rpt map[string]any
	json.Unmarshal(w.Body.Bytes(), &rpt)
	if _, ok := rpt["sections"]; !ok {
		t.Error("report missing sections key")
	}
	if _, ok := rpt["findings"]; !ok {
		t.Error("report missing findings key")
	}
}

func TestGroupAPI(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	// Create group.
	body := `{"name":"prod","clusters":["east","west"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create group: status %d, body: %s", w.Code, w.Body.String())
	}

	// List groups.
	req = httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list groups: status %d", w.Code)
	}

	var groups []map[string]any
	json.Unmarshal(w.Body.Bytes(), &groups)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	// Delete group.
	req = httptest.NewRequest(http.MethodDelete, "/api/groups/prod", nil)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("delete group: status %d", w.Code)
	}
}

func TestStaticIndex(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("index: status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Fleetsweeper") {
		t.Error("index missing Fleetsweeper title")
	}
}
