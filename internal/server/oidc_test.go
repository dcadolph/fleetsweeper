package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestSessionCookieRoundTrip verifies encode then decode returns the same payload.
func TestSessionCookieRoundTrip(t *testing.T) {
	t.Parallel()
	in := sessionPayload{
		Subject:   "alice@example.com",
		Role:      store.RoleOperator,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	encoded, err := encodeSession(in, "test-secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := decodeSession(encoded, "test-secret")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Subject != in.Subject || out.Role != in.Role || out.ExpiresAt != in.ExpiresAt {
		t.Errorf("mismatch: %+v vs %+v", out, in)
	}
}

// TestSessionCookieTamper verifies a flipped byte invalidates the signature.
func TestSessionCookieTamper(t *testing.T) {
	t.Parallel()
	encoded, _ := encodeSession(sessionPayload{Subject: "x", Role: "admin", ExpiresAt: time.Now().Add(time.Hour).Unix()}, "secret")
	tampered := encoded[:len(encoded)-2] + "aa"
	if _, err := decodeSession(tampered, "secret"); err == nil {
		t.Error("expected signature error on tampered cookie")
	}
}

// TestSessionCookieExpired verifies past-due sessions are rejected.
func TestSessionCookieExpired(t *testing.T) {
	t.Parallel()
	encoded, _ := encodeSession(sessionPayload{Subject: "x", Role: "viewer", ExpiresAt: time.Now().Add(-time.Hour).Unix()}, "secret")
	if _, err := decodeSession(encoded, "secret"); err == nil {
		t.Error("expected expiry error on stale cookie")
	}
}

// TestClaimMatch covers the supported claim shapes.
func TestClaimMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Claims  map[string]any
		Pattern string
		Want    bool
	}{{
		Name: "Test 0: String exact.", Claims: map[string]any{"email": "a@b"}, Pattern: "email:a@b", Want: true,
	}, {
		Name: "Test 1: String mismatch.", Claims: map[string]any{"email": "a@b"}, Pattern: "email:c@d", Want: false,
	}, {
		Name: "Test 2: Slice contains.", Claims: map[string]any{"groups": []any{"x", "fleetsweeper-admins"}}, Pattern: "groups:fleetsweeper-admins", Want: true,
	}, {
		Name: "Test 3: Slice excludes.", Claims: map[string]any{"groups": []any{"x"}}, Pattern: "groups:y", Want: false,
	}, {
		Name: "Test 4: Empty pattern is no-op.", Claims: map[string]any{"email": "a"}, Pattern: "", Want: false,
	}, {
		Name: "Test 5: Malformed pattern.", Claims: map[string]any{"x": "y"}, Pattern: "no-colon", Want: false,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := claimMatch(test.Claims, test.Pattern); got != test.Want {
				t.Errorf("test %d: want %v, got %v", i, test.Want, got)
			}
		})
	}
}

// TestActorFromSessionCookie verifies a valid cookie populates the actor in
// the request context, and that GET admin endpoints honor the cookie role.
func TestActorFromSessionCookie(t *testing.T) {
	t.Parallel()
	srv := newOIDCTestServer(t)

	encoded, _ := encodeSession(sessionPayload{
		Subject:   "ops@example.com",
		Role:      store.RoleAdmin,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, "session-test-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/whoami", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: encoded})
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("whoami via cookie: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"role":"admin"`) {
		t.Errorf("expected admin role in body: %s", w.Body.String())
	}
}

// TestSessionCookieRejectedWhenInvalid verifies a junk cookie does not
// promote the caller; the response falls back to viewer (403 on admin GET).
func TestSessionCookieRejectedWhenInvalid(t *testing.T) {
	t.Parallel()
	srv := newOIDCTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/whoami", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "garbage.signature"})
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("junk cookie: want 403, got %d", w.Code)
	}
}

// newOIDCTestServer builds a Server with an OIDC runtime whose session
// secret is set to a known value, but with the provider/verifier left nil
// since these tests exercise only cookie validation, not the IdP dance.
func newOIDCTestServer(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc.db")
	st, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := New(Config{
		Store:    st,
		Registry: scanner.NewRegistry(),
		Log:      zap.NewNop(),
		Workers:  2,
	})
	srv.oidc = &oidcRuntime{cfg: OIDCConfig{SessionSecret: "session-test-secret"}}
	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})
	return srv
}
