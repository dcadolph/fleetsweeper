package server

import (
	"net/http"
	"slices"
	"time"

	"go.uber.org/zap"
)

// contentSecurityPolicy lets the dashboard load scripts, styles, images, and data only from its
// own origin. Inline script and style stay allowed until the dashboard moves to ES modules; the
// globe's WebGL textures and workers need data: and blob: URLs.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; " +
	"worker-src 'self' blob:; font-src 'self' data:; object-src 'none'; base-uri 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders sets the Content-Security-Policy and stops browsers from sniffing a response
// into a different content type, on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// jsonMiddleware sets the Content-Type header for API responses.
func jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware echoes back the request Origin when it matches the allowlist.
// When the allowlist is empty no CORS headers are emitted, so browsers refuse
// cross-origin requests by default.
func corsMiddleware(allowOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(allowOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request as an info-level structured entry.
func loggingMiddleware(log *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", sw.status),
			zap.Duration("duration", time.Since(start)),
		)
	})
}

// statusWriter wraps ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	// status is the HTTP status code written.
	status int
}

// WriteHeader captures the status code.
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// FlushError flushes the underlying writer and reports http.ErrNotSupported when it cannot,
// so streaming handlers behind this wrapper can tell whether their bytes reached the client.
func (w *statusWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Flush flushes the underlying writer when it supports flushing.
func (w *statusWriter) Flush() {
	_ = w.FlushError()
}

// Unwrap returns the wrapped writer so http.ResponseController can reach deadlines and
// hijacking on the underlying connection.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
