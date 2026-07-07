package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleOpenAPI_ServesSpec verifies the embedded OpenAPI document is
// served verbatim with a YAML content type.
func TestHandleOpenAPI_ServesSpec(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("content type want yaml, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "openapi") {
		t.Error("body does not look like an OpenAPI document")
	}
}
