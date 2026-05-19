package server

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// auditMiddleware records every mutating request in the audit_log table.
// Read-only requests are intentionally skipped: they already appear in the
// process log and would balloon the table.
func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresWrite(r) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		captured := &auditWriter{ResponseWriter: w, status: http.StatusOK, body: &bytes.Buffer{}}
		next.ServeHTTP(captured, r)
		duration := time.Since(start)

		actor := actorFromContext(r.Context())
		entry := store.AuditEntry{
			Timestamp:  start.UTC(),
			ActorID:    actor.ID,
			ActorName:  actor.Name,
			ActorRole:  actor.Role,
			Method:     r.Method,
			Path:       r.URL.Path,
			Status:     captured.status,
			RemoteAddr: r.RemoteAddr,
			UserAgent:  r.Header.Get("User-Agent"),
			DurationMS: duration.Milliseconds(),
		}
		if captured.status >= 400 {
			entry.Error = extractErrorMessage(captured.body.Bytes())
		}

		auditCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.store.SaveAuditEntry(auditCtx, entry); err != nil {
			s.log.Warn("audit: save failed", zap.Error(err))
		}
	})
}

// auditWriter wraps http.ResponseWriter to capture status and (when small) the
// response body so the audit middleware can record a short error excerpt.
type auditWriter struct {
	http.ResponseWriter
	// status is the HTTP status code written.
	status int
	// body buffers the response body up to auditBodyCap bytes.
	body *bytes.Buffer
}

// auditBodyCap limits how many bytes we buffer for the audit log error excerpt.
const auditBodyCap = 512

// WriteHeader captures the status code before delegating.
func (w *auditWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Write streams to the underlying writer and snapshots into the body buffer
// while it has room. The snapshot is bounded so a large response body cannot
// blow out memory.
func (w *auditWriter) Write(p []byte) (int, error) {
	if w.body.Len() < auditBodyCap {
		remaining := auditBodyCap - w.body.Len()
		if remaining > len(p) {
			remaining = len(p)
		}
		w.body.Write(p[:remaining])
	}
	return w.ResponseWriter.Write(p)
}

// extractErrorMessage pulls the "error" field from a JSON error body without
// importing encoding/json overhead for the common case. The audit log only
// needs a short excerpt for at-a-glance triage; the request log carries the
// full detail.
func extractErrorMessage(body []byte) string {
	const needle = `"error":"`
	idx := bytes.Index(body, []byte(needle))
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		if len(rest) > 200 {
			return string(rest[:200])
		}
		return string(rest)
	}
	if end > 200 {
		end = 200
	}
	return string(rest[:end])
}
