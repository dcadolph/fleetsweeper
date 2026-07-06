package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a token-bucket rate limiter keyed by actor identity (or
// remote address for anonymous traffic). One bucket per key; buckets
// refill at a configurable rate.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket

	// readRPM is the per-key budget for GET/HEAD/OPTIONS requests.
	readRPM int
	// writeRPM is the per-key budget for mutating requests.
	writeRPM int
	// burst is the maximum bucket size; controls how bursty traffic can be.
	burst int
}

// tokenBucket tracks one key's available tokens and last refill time.
type tokenBucket struct {
	// tokens is the current token count.
	tokens float64
	// lastRefill is when the bucket was last refilled.
	lastRefill time.Time
}

// newRateLimiter builds a limiter with the supplied per-minute budgets.
// readRPM <= 0 disables read limiting; writeRPM <= 0 disables write limiting.
// burst defaults to the larger of the two budgets.
func newRateLimiter(readRPM, writeRPM int) *rateLimiter {
	burst := max(writeRPM, readRPM)
	if burst <= 0 {
		burst = 60
	}
	return &rateLimiter{
		buckets:  make(map[string]*tokenBucket),
		readRPM:  readRPM,
		writeRPM: writeRPM,
		burst:    burst,
	}
}

// allow consumes one token for the supplied key under the limit
// appropriate to the request. Returns the remaining tokens and whether
// the request should proceed.
func (r *rateLimiter) allow(key string, write bool) (remaining float64, ok bool) {
	limit := r.readRPM
	if write {
		limit = r.writeRPM
	}
	if limit <= 0 {
		return -1, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, exists := r.buckets[key]
	now := time.Now()
	if !exists {
		b = &tokenBucket{tokens: float64(r.burst), lastRefill: now}
		r.buckets[key] = b
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * float64(limit) / 60.0
		if b.tokens > float64(r.burst) {
			b.tokens = float64(r.burst)
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return b.tokens, false
	}
	b.tokens--
	return b.tokens, true
}

// rateLimitMiddleware enforces the limiter on every request. Buckets are
// keyed by actor.ID when authenticated, otherwise by transport remote
// host so anonymous traffic still gets a fair share.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	if s.rateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := rateLimitKey(r)
		write := requiresWrite(r)
		remaining, ok := s.rateLimiter.allow(key, write)
		if !ok {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded; retry shortly")
			return
		}
		if remaining >= 0 {
			w.Header().Set("X-RateLimit-Remaining", formatRemaining(remaining))
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitKey derives a bucket key from the request. When an Actor has
// been attached to the context by the auth middleware, its ID is used so
// per-key limits scale with the number of distinct callers. Otherwise the
// transport's remote host (without port) is the key.
func rateLimitKey(r *http.Request) string {
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil && a.ID != "" {
		return "actor:" + a.ID
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "addr:" + host
}

// formatRemaining renders a fractional token count as a stable header value.
// Clients only care about ceiling for retry decisions; we expose the
// integer floor to keep the header stable across rapid scrapes.
func formatRemaining(tokens float64) string {
	n := int(tokens)
	switch n {
	case 0:
		return "0"
	default:
		return itoaSimple(n)
	}
}

// itoaSimple is a small base-10 integer formatter that avoids importing
// strconv for one call. Negative inputs are clamped to 0.
func itoaSimple(n int) string {
	if n <= 0 {
		return "0"
	}
	if n < 10 {
		return string('0' + byte(n))
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(buf[i:])
}
