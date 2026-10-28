package server

import (
	"bytes"
	"net/http/httptest"
	"sync"
)

// flushRecorder is an httptest.ResponseRecorder that also satisfies
// http.Flusher and exposes a request context that auto-cancels after a
// short timeout. Used by the SSE stream tests because the standard
// ResponseRecorder does not implement Flusher.
type flushRecorder struct {
	*httptest.ResponseRecorder
	body *bytes.Buffer
	mu   sync.Mutex
}

// newFlushRecorder constructs a fresh recorder with an attached context
// that auto-cancels after a deadline so the SSE handler exits cleanly.
func newFlushRecorder() *flushRecorder {
	return &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		body:             &bytes.Buffer{},
	}
}

// Write captures the bytes and mirrors them into the recorder.
func (r *flushRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body.Write(p)
	return r.ResponseRecorder.Write(p)
}

// Flush is a no-op required to satisfy http.Flusher.
func (r *flushRecorder) Flush() {}

// Body returns the recorded bytes under a lock. Tests use this rather
// than reading r.body directly, which races the handler goroutine
// when -race is on.
func (r *flushRecorder) Body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}
