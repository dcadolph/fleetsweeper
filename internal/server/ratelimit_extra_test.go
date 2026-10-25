package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimitKey covers address keying, the trusted proxy header, and its fallbacks.
func TestRateLimitKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		RemoteAddr  string
		ProxyHeader string
		Forwarded   string
		WantResult  string
	}{{ // Test 0: Remote host without the port.
		RemoteAddr: "10.0.0.9:55555", WantResult: "addr:10.0.0.9",
	}, { // Test 1: Malformed RemoteAddr falls back to the raw value.
		RemoteAddr: "unix-socket", WantResult: "addr:unix-socket",
	}, { // Test 2: A forwarded header is ignored unless it is trusted.
		RemoteAddr: "10.0.0.9:1", Forwarded: "203.0.113.7", WantResult: "addr:10.0.0.9",
	}, { // Test 3: A trusted header with one address keys on it.
		RemoteAddr: "10.0.0.9:1", ProxyHeader: "X-Forwarded-For", Forwarded: "203.0.113.7",
		WantResult: "addr:203.0.113.7",
	}, { // Test 4: A trusted header keys on the last entry, the one the proxy appended.
		RemoteAddr: "10.0.0.9:1", ProxyHeader: "X-Forwarded-For", Forwarded: "1.1.1.1, 203.0.113.7",
		WantResult: "addr:203.0.113.7",
	}, { // Test 5: A trusted header that is missing falls back to the remote host.
		RemoteAddr: "10.0.0.9:1", ProxyHeader: "X-Forwarded-For", WantResult: "addr:10.0.0.9",
	}, { // Test 6: A trusted header that is not an IP falls back to the remote host.
		RemoteAddr: "10.0.0.9:1", ProxyHeader: "X-Forwarded-For", Forwarded: "evil, not-an-ip",
		WantResult: "addr:10.0.0.9",
	}, { // Test 7: IPv6 entries are normalized.
		RemoteAddr: "[::1]:80", ProxyHeader: "X-Forwarded-For", Forwarded: "2001:DB8::1",
		WantResult: "addr:2001:db8::1",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
			req.RemoteAddr = test.RemoteAddr
			if test.Forwarded != "" {
				req.Header.Set("X-Forwarded-For", test.Forwarded)
			}
			if got := rateLimitKey(req, test.ProxyHeader); got != test.WantResult {
				t.Errorf("want %q, got %q", test.WantResult, got)
			}
		})
	}
}

// TestFormatRemaining covers the header rendering of fractional token counts,
// including the zero and negative clamps.
func TestFormatRemaining(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		In         float64
		WantResult string
	}{{ // Test 0: Fraction floors to zero.
		Name: "sub one", In: 0.7, WantResult: "0",
	}, { // Test 1: Single digit.
		Name: "single", In: 5.9, WantResult: "5",
	}, { // Test 2: Multi digit.
		Name: "multi", In: 123.0, WantResult: "123",
	}, { // Test 3: Negative clamps to zero.
		Name: "negative", In: -4.0, WantResult: "0",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := formatRemaining(test.In); got != test.WantResult {
				t.Errorf("test %d: want %q, got %q", i, test.WantResult, got)
			}
		})
	}
}

// TestRateLimitMiddleware_RemainingHeader verifies an allowed request carries
// the X-RateLimit-Remaining header when limiting is enabled.
func TestRateLimitMiddleware_RemainingHeader(t *testing.T) {
	t.Parallel()
	srv := newRateLimitedTestServer(t, 60, 60)
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("expected X-RateLimit-Remaining header on allowed read")
	}
}
