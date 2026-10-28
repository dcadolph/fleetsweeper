package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteJSON_MarshalError verifies an unmarshalable value produces a 500
// rather than a partial body.
func TestWriteJSON_MarshalError(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, make(chan int))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500 on marshal failure, got %d", w.Code)
	}
}

// TestHandleDeleteGroup_NotFound verifies deleting an unknown group 404s.
func TestHandleDeleteGroup_NotFound(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/groups/ghost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}
