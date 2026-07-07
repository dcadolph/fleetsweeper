package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// okHandler is a trivial next handler that records whether it ran and writes
// a fixed 200 body.
func okHandler(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestCORSMiddleware covers origin echoing, the non-allowlisted case, and the
// OPTIONS preflight short-circuit.
func TestCORSMiddleware(t *testing.T) {
	t.Parallel()
	allow := []string{"https://app.example"}
	tests := []struct {
		Name       string
		Method     string
		Origin     string
		WantStatus int
		WantACAO   string
		WantNext   bool
	}{{ // Test 0: Allowed origin is echoed and request proceeds.
		Name: "allowed", Method: http.MethodGet, Origin: "https://app.example",
		WantStatus: http.StatusOK, WantACAO: "https://app.example", WantNext: true,
	}, { // Test 1: Disallowed origin gets no CORS header but still proceeds.
		Name: "disallowed", Method: http.MethodGet, Origin: "https://evil.example",
		WantStatus: http.StatusOK, WantACAO: "", WantNext: true,
	}, { // Test 2: No Origin header emits no CORS headers.
		Name: "no origin", Method: http.MethodGet, Origin: "",
		WantStatus: http.StatusOK, WantACAO: "", WantNext: true,
	}, { // Test 3: OPTIONS preflight short-circuits with 204 and never calls next.
		Name: "preflight", Method: http.MethodOptions, Origin: "https://app.example",
		WantStatus: http.StatusNoContent, WantACAO: "https://app.example", WantNext: false,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			ran := false
			h := corsMiddleware(allow, okHandler(&ran))
			req := httptest.NewRequest(test.Method, "/api/scans", nil)
			if test.Origin != "" {
				req.Header.Set("Origin", test.Origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("test %d: status want %d, got %d", i, test.WantStatus, w.Code)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != test.WantACAO {
				t.Errorf("test %d: ACAO want %q, got %q", i, test.WantACAO, got)
			}
			if ran != test.WantNext {
				t.Errorf("test %d: next ran = %v, want %v", i, ran, test.WantNext)
			}
		})
	}
}

// TestLoggingMiddleware_CapturesStatus verifies the wrapped writer records the
// downstream status and the response body reaches the client.
func TestLoggingMiddleware_CapturesStatus(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brew"))
	})
	h := loggingMiddleware(zap.NewNop(), next)
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTeapot {
		t.Errorf("status want 418, got %d", w.Code)
	}
	if w.Body.String() != "brew" {
		t.Errorf("body want brew, got %q", w.Body.String())
	}
}

// TestJSONMiddleware_SetsContentType verifies the JSON content type is applied.
func TestJSONMiddleware_SetsContentType(t *testing.T) {
	t.Parallel()
	var ran bool
	h := jsonMiddleware(okHandler(&ran))
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type: %q", got)
	}
	if !ran {
		t.Error("next handler should run")
	}
}
