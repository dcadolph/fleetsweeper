package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestRateLimiterAllow verifies the bucket admits up to the burst, then
// rejects, then admits again as tokens refill.
func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(60, 60) // 60 rpm each, burst = 60
	for i := range 60 {
		if _, ok := rl.allow("k", false); !ok {
			t.Fatalf("request %d rejected", i)
		}
	}
	if _, ok := rl.allow("k", false); ok {
		t.Error("burst should be exhausted")
	}
}

// TestRateLimiterDisabled verifies a zero budget never rejects.
func TestRateLimiterDisabled(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(0, 0)
	for i := range 1000 {
		if _, ok := rl.allow("k", false); !ok {
			t.Fatalf("zero-budget should never reject (request %d)", i)
		}
	}
}

// TestRateLimitMiddleware429 verifies the middleware returns 429 after the
// budget is exhausted and sets the Retry-After header.
func TestRateLimitMiddleware429(t *testing.T) {
	t.Parallel()
	srv := newRateLimitedTestServer(t, 2, 1)

	// One write request should pass.
	req := httptest.NewRequest(http.MethodPost, "/api/groups",
		strings.NewReader(`{"name":"g1","clusters":[]}`))
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first write: want 201, got %d", w.Code)
	}

	// Burst (write=1, burst=2) lets one more pass, then 429.
	for range 5 {
		req = httptest.NewRequest(http.MethodPost, "/api/groups",
			strings.NewReader(`{"name":"g","clusters":[]}`))
		req.Header.Set("Authorization", "Bearer bootstrap-secret")
		w = httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			if w.Header().Get("Retry-After") == "" {
				t.Error("429 response missing Retry-After")
			}
			return
		}
	}
	t.Error("expected 429 within 5 attempts")
}

// newRateLimitedTestServer builds a Server with the supplied per-actor
// read/write budgets in place. Uses an SQLite store under a temp dir.
func newRateLimitedTestServer(t *testing.T, readRPM, writeRPM int) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rl.db")
	st, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := New(Config{
		Store:     st,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "bootstrap-secret",
		ReadRPM:   readRPM,
		WriteRPM:  writeRPM,
	})
	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})
	return srv
}
