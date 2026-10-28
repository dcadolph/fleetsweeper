package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

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

const (
	testOIDCIssuer = "https://issuer.example.com"
	testOIDCSecret = "callback-test-secret"
)

// testOIDCSignedToken returns an RS256 JWT for the claims signed with key.
func testOIDCSignedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

// TestHandleOIDCCallback drives the callback handler against a fake token endpoint.
func TestHandleOIDCCallback(t *testing.T) {
	t.Parallel()
	goodKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	baseClaims := func(extra map[string]any) map[string]any {
		c := map[string]any{
			"iss": testOIDCIssuer,
			"aud": "c",
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	tests := []struct {
		Name        string
		StateCookie string
		StateQuery  string
		Code        string
		TokenStatus int
		SignKey     *rsa.PrivateKey
		OmitIDToken bool
		NoOIDC      bool
		Claims      map[string]any
		AdminClaim  string
		OperClaim   string
		WantStatus  int
		WantSubject string
		WantRole    string
	}{{ // Test 0: No state cookie.
		StateQuery: "s", Code: "abc", WantStatus: http.StatusBadRequest,
	}, { // Test 1: State mismatch.
		StateCookie: "s", StateQuery: "other", Code: "abc", WantStatus: http.StatusBadRequest,
	}, { // Test 2: Missing code.
		StateCookie: "s", StateQuery: "s", WantStatus: http.StatusBadRequest,
	}, { // Test 3: Token endpoint returns 500.
		StateCookie: "s", StateQuery: "s", Code: "abc", TokenStatus: http.StatusInternalServerError,
		WantStatus: http.StatusUnauthorized,
	}, { // Test 4: Response without id_token.
		StateCookie: "s", StateQuery: "s", Code: "abc", OmitIDToken: true,
		WantStatus: http.StatusUnauthorized,
	}, { // Test 5: id_token signed by another key.
		StateCookie: "s", StateQuery: "s", Code: "abc", SignKey: otherKey,
		Claims: baseClaims(nil), WantStatus: http.StatusUnauthorized,
	}, { // Test 6: Admin claim match.
		StateCookie: "s", StateQuery: "s", Code: "abc",
		Claims:     baseClaims(map[string]any{"email": "a@example.com", "groups": []any{"adm"}}),
		AdminClaim: "groups:adm", OperClaim: "groups:ops",
		WantStatus: http.StatusFound, WantSubject: "a@example.com", WantRole: store.RoleAdmin,
	}, { // Test 7: Operator claim match.
		StateCookie: "s", StateQuery: "s", Code: "abc",
		Claims:     baseClaims(map[string]any{"email": "o@example.com", "groups": []any{"ops"}}),
		AdminClaim: "groups:adm", OperClaim: "groups:ops",
		WantStatus: http.StatusFound, WantSubject: "o@example.com", WantRole: store.RoleOperator,
	}, { // Test 8: No claim match uses the default role.
		StateCookie: "s", StateQuery: "s", Code: "abc",
		Claims:     baseClaims(map[string]any{"email": "v@example.com", "groups": []any{"x"}}),
		AdminClaim: "groups:adm", OperClaim: "groups:ops",
		WantStatus: http.StatusFound, WantSubject: "v@example.com", WantRole: store.RoleViewer,
	}, { // Test 9: No email claim falls back to sub.
		StateCookie: "s", StateQuery: "s", Code: "abc",
		Claims:     baseClaims(nil),
		AdminClaim: "groups:adm", OperClaim: "groups:ops",
		WantStatus: http.StatusFound, WantSubject: "user-1", WantRole: store.RoleViewer,
	}, { // Test 10: OIDC not configured.
		NoOIDC: true, WantStatus: http.StatusNotFound,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			key := test.SignKey
			if key == nil {
				key = goodKey
			}
			handler := func(w http.ResponseWriter, _ *http.Request) {
				if test.TokenStatus != 0 {
					http.Error(w, "boom", test.TokenStatus)
					return
				}
				resp := map[string]any{"access_token": "at", "token_type": "Bearer"}
				if !test.OmitIDToken {
					resp["id_token"] = testOIDCSignedToken(t, key, test.Claims)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}
			tokenSrv := httptest.NewServer(http.HandlerFunc(handler))
			defer tokenSrv.Close()

			verifier := oidc.NewVerifier(testOIDCIssuer, &oidc.StaticKeySet{
				PublicKeys: []crypto.PublicKey{&goodKey.PublicKey},
			}, &oidc.Config{ClientID: "c"})
			srv := &Server{log: zap.NewNop(), oidc: &oidcRuntime{
				cfg: OIDCConfig{
					SessionSecret:   testOIDCSecret,
					SessionLifetime: time.Hour,
					AdminClaim:      test.AdminClaim,
					OperatorClaim:   test.OperClaim,
					DefaultRole:     store.RoleViewer,
				},
				verifier: verifier,
				oauth2cfg: &oauth2.Config{
					ClientID:     "c",
					ClientSecret: "secret",
					Endpoint:     oauth2.Endpoint{TokenURL: tokenSrv.URL},
				},
			}}
			if test.NoOIDC {
				srv.oidc = nil
			}

			target := "/oidc/callback?state=" + url.QueryEscape(test.StateQuery)
			if test.Code != "" {
				target += "&code=" + url.QueryEscape(test.Code)
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			if test.StateCookie != "" {
				req.AddCookie(&http.Cookie{Name: stateCookieName, Value: test.StateCookie})
			}
			rec := httptest.NewRecorder()
			srv.handleOIDCCallback(rec, req)

			if diff := cmp.Diff(test.WantStatus, rec.Code); diff != "" {
				t.Fatalf("status mismatch (-want +got):\n%s", diff)
			}
			var session *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == sessionCookieName {
					session = c
				}
			}
			if test.WantStatus != http.StatusFound {
				if session != nil {
					t.Errorf("unexpected session cookie on failure")
				}
				return
			}
			if session == nil {
				t.Fatal("missing session cookie")
			}
			got, err := decodeSession(session.Value, testOIDCSecret)
			if err != nil {
				t.Fatalf("decode session: %v", err)
			}
			want := sessionPayload{Subject: test.WantSubject, Role: test.WantRole}
			got.ExpiresAt = 0
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("session mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
