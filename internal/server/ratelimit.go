package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bucketIdleTTL is how long a bucket may sit unused before the limiter evicts it. An evicted
// key starts again with a full bucket, which is what it would have refilled to anyway.
const bucketIdleTTL = 10 * time.Minute

// bucketSweepInterval is the minimum time between eviction sweeps of the bucket map.
const bucketSweepInterval = time.Minute

// rateLimiter is a token-bucket rate limiter keyed by client address. Reads and writes draw
// from separate buckets, each holding one minute of its own budget.
type rateLimiter struct {
	// mu guards buckets and lastSweep.
	mu sync.Mutex
	// buckets maps a client key plus request class to its bucket.
	buckets map[string]*tokenBucket
	// lastSweep is when idle buckets were last evicted.
	lastSweep time.Time
	// readRPM is the per-key budget for GET/HEAD/OPTIONS requests.
	readRPM int
	// writeRPM is the per-key budget for mutating requests.
	writeRPM int
	// now returns the current time. Tests replace it to move the clock.
	now func() time.Time
}

// tokenBucket tracks one key's available tokens and last refill time.
type tokenBucket struct {
	// tokens is the current token count.
	tokens float64
	// lastRefill is when the bucket was last refilled.
	lastRefill time.Time
}

// newRateLimiter builds a limiter with the supplied per-minute budgets. readRPM <= 0 disables
// read limiting and writeRPM <= 0 disables write limiting.
func newRateLimiter(readRPM, writeRPM int) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*tokenBucket),
		readRPM:  readRPM,
		writeRPM: writeRPM,
		now:      time.Now,
	}
}

// allow consumes one token for the supplied key under the limit appropriate to the request.
// It returns the remaining tokens, or -1 when the class is unlimited, and whether the request
// should proceed.
func (r *rateLimiter) allow(key string, write bool) (remaining float64, ok bool) {
	limit, class := r.readRPM, "|r"
	if write {
		limit, class = r.writeRPM, "|w"
	}
	if limit <= 0 {
		return -1, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweep(now)
	key += class
	b, exists := r.buckets[key]
	if !exists {
		b = &tokenBucket{tokens: float64(limit), lastRefill: now}
		r.buckets[key] = b
	}
	if elapsed := now.Sub(b.lastRefill).Seconds(); elapsed > 0 {
		b.tokens = min(b.tokens+elapsed*float64(limit)/60.0, float64(limit))
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return b.tokens, false
	}
	b.tokens--
	return b.tokens, true
}

// sweep evicts buckets idle for longer than bucketIdleTTL, at most once per
// bucketSweepInterval. The caller holds r.mu.
func (r *rateLimiter) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < bucketSweepInterval {
		return
	}
	r.lastSweep = now
	for k, b := range r.buckets {
		if now.Sub(b.lastRefill) > bucketIdleTTL {
			delete(r.buckets, k)
		}
	}
}

// size returns the number of live buckets.
func (r *rateLimiter) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// rateLimitMiddleware enforces the limiter on every request. It runs before authentication so
// requests carrying bad tokens are throttled like any other, and the bucket is keyed by client
// address because no actor is known yet.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	if s.rateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remaining, ok := s.rateLimiter.allow(rateLimitKey(r, s.trustedProxyHeader), requiresWrite(r))
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

// rateLimitKey derives a bucket key from the client address. When proxyHeader is set, the last
// address in that header is used, since it is the one the trusted proxy appended; a header that
// is missing or does not hold an IP falls back to the transport's remote host.
func rateLimitKey(r *http.Request, proxyHeader string) string {
	if proxyHeader != "" {
		if v := r.Header.Get(proxyHeader); v != "" {
			last := strings.TrimSpace(v[strings.LastIndex(v, ",")+1:])
			if ip := net.ParseIP(last); ip != nil {
				return "addr:" + ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "addr:" + host
}

// formatRemaining renders a fractional token count as its integer floor, clamped at zero, so
// the header stays stable across rapid requests.
func formatRemaining(tokens float64) string {
	return strconv.Itoa(max(int(tokens), 0))
}
