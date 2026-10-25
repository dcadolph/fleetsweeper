package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

// TestRateLimiterEvictsIdleBuckets verifies buckets idle past bucketIdleTTL are evicted by the
// next sweep, so the map holds at most the keys seen within the idle window plus one sweep
// interval, while buckets inside the window survive.
func TestRateLimiterEvictsIdleBuckets(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(60, 60)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return now }
	for i := range 1000 {
		rl.allow(fmt.Sprintf("addr:10.0.%d.%d", i/256, i%256), false)
	}
	if got := rl.size(); got != 1000 {
		t.Fatalf("want 1000 buckets, got %d", got)
	}

	now = now.Add(bucketIdleTTL - time.Second)
	rl.allow("addr:fresh-1", false)
	if got := rl.size(); got != 1001 {
		t.Errorf("inside the idle window: want 1001 buckets, got %d", got)
	}

	now = now.Add(bucketSweepInterval + time.Second)
	rl.allow("addr:fresh-2", false)
	if got := rl.size(); got != 2 {
		t.Errorf("past the idle window: want 2 buckets, got %d", got)
	}
}

// TestRateLimiterSeparateClasses verifies exhausting the write budget leaves reads untouched,
// and that each class bursts to exactly one minute of its own budget.
func TestRateLimiterSeparateClasses(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(10, 3)
	for i := range 3 {
		if _, ok := rl.allow("k", true); !ok {
			t.Fatalf("write %d rejected inside the budget", i)
		}
	}
	if _, ok := rl.allow("k", true); ok {
		t.Error("fourth write should be rejected")
	}
	for i := range 10 {
		if _, ok := rl.allow("k", false); !ok {
			t.Fatalf("read %d rejected after writes were exhausted", i)
		}
	}
	if _, ok := rl.allow("k", false); ok {
		t.Error("eleventh read should be rejected")
	}
}

// TestRateLimitThrottlesBadTokens verifies the limiter runs before authentication, so a client
// guessing tokens is throttled after its write budget even though every attempt fails auth.
func TestRateLimitThrottlesBadTokens(t *testing.T) {
	t.Parallel()
	srv := newRateLimitedTestServer(t, 0, 3)
	var codes []int
	for range 5 {
		req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"g"}`))
		req.Header.Set("Authorization", "Bearer wrong-guess")
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	want := []int{
		http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized,
		http.StatusTooManyRequests, http.StatusTooManyRequests,
	}
	if diff := cmp.Diff(want, codes); diff != "" {
		t.Errorf("status sequence mismatch (-want +got):\n%s", diff)
	}
}

// TestRateLimitTrustedProxyHeader verifies clients behind one proxy get separate buckets when
// the proxy header is trusted, and share the proxy's bucket when it is not.
func TestRateLimitTrustedProxyHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ProxyHeader string
		WantSecond  int
	}{{ // Test 0: Untrusted header, both clients share the proxy address.
		ProxyHeader: "", WantSecond: http.StatusTooManyRequests,
	}, { // Test 1: Trusted header, each client has its own bucket.
		ProxyHeader: "X-Forwarded-For", WantSecond: http.StatusOK,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv := newRateLimitedTestServer(t, 1, 0)
			srv.trustedProxyHeader = test.ProxyHeader
			var got []int
			for _, client := range []string{"203.0.113.1", "203.0.113.2"} {
				req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
				req.RemoteAddr = "10.0.0.1:443"
				req.Header.Set("X-Forwarded-For", client)
				w := httptest.NewRecorder()
				srv.mux.ServeHTTP(w, req)
				got = append(got, w.Code)
			}
			if diff := cmp.Diff([]int{http.StatusOK, test.WantSecond}, got); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
