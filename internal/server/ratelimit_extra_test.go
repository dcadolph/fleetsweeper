package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimitKey covers actor-keyed, address-keyed, and malformed-address
// derivations of the limiter bucket key.
func TestRateLimitKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Actor      *Actor
		RemoteAddr string
		WantResult string
	}{{ // Test 0: Authenticated actor keys by ID.
		Name: "actor id", Actor: &Actor{ID: "key_1"}, RemoteAddr: "1.2.3.4:9",
		WantResult: "actor:key_1",
	}, { // Test 1: No actor keys by remote host without the port.
		Name: "addr with port", Actor: nil, RemoteAddr: "10.0.0.9:55555",
		WantResult: "addr:10.0.0.9",
	}, { // Test 2: Malformed RemoteAddr falls back to the raw value.
		Name: "addr no port", Actor: nil, RemoteAddr: "unix-socket",
		WantResult: "addr:unix-socket",
	}, { // Test 3: Actor present but empty ID falls back to address.
		Name: "empty actor id", Actor: &Actor{ID: ""}, RemoteAddr: "8.8.8.8:1",
		WantResult: "addr:8.8.8.8",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
			req.RemoteAddr = test.RemoteAddr
			if test.Actor != nil {
				req = req.WithContext(withActor(context.Background(), test.Actor))
			}
			if got := rateLimitKey(req); got != test.WantResult {
				t.Errorf("test %d: want %q, got %q", i, test.WantResult, got)
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

// TestItoaSimple covers the small base-10 formatter across its branches.
func TestItoaSimple(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         int
		WantResult string
	}{
		{In: 0, WantResult: "0"},       // Test 0: Zero.
		{In: -3, WantResult: "0"},      // Test 1: Negative clamps.
		{In: 7, WantResult: "7"},       // Test 2: Single digit.
		{In: 10, WantResult: "10"},     // Test 3: Two digits.
		{In: 2048, WantResult: "2048"}, // Test 4: Multi digit.
	}
	for i, test := range tests {
		if got := itoaSimple(test.In); got != test.WantResult {
			t.Errorf("test %d: itoaSimple(%d) want %q, got %q", i, test.In, test.WantResult, got)
		}
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
