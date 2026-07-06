package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// OIDCConfig configures the OIDC login flow. All fields are required when
// OIDC is enabled; the auth middleware silently ignores cookies when
// OIDCConfig.SessionSecret is empty.
type OIDCConfig struct {
	// IssuerURL is the OIDC discovery URL (e.g. https://accounts.google.com).
	IssuerURL string
	// ClientID identifies the fleetsweeper application at the IdP.
	ClientID string
	// ClientSecret is the matching client secret.
	ClientSecret string
	// RedirectURL is fleetsweeper's callback URL, e.g.
	// https://fleetsweeper.example.com/oidc/callback. Must be registered
	// with the IdP exactly.
	RedirectURL string
	// Scopes requested. Defaults to openid + email + profile.
	Scopes []string
	// SessionSecret is the HMAC-SHA256 key used to sign session cookies.
	// Treat as a long-term server secret.
	SessionSecret string
	// SessionLifetime is the cookie validity window. Defaults to 8 hours.
	SessionLifetime time.Duration
	// AdminClaim is the JWT claim consulted to assign the admin role.
	// Format: "<claim_name>:<value>" — e.g. "groups:fleetsweeper-admins"
	// or "email:ops@example.com". Empty disables admin promotion via OIDC.
	AdminClaim string
	// OperatorClaim is the JWT claim for the operator role. Empty disables.
	OperatorClaim string
	// DefaultRole is the role granted to authenticated users who match no
	// claim mapping. Defaults to viewer.
	DefaultRole string
}

// oidcRuntime holds the runtime state for the OIDC flow. Built once at
// server construction and reused across requests.
type oidcRuntime struct {
	cfg       OIDCConfig
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth2cfg *oauth2.Config
}

// sessionCookieName is the name of the cookie that carries the signed
// fleetsweeper session.
const sessionCookieName = "fleetsweeper_session"

// stateCookieName is the short-lived cookie that ties an outbound OIDC
// redirect to its callback so state cannot be replayed across browsers.
const stateCookieName = "fleetsweeper_oidc_state"

// initOIDC builds the OIDC runtime from cfg. Returns nil when OIDC is not
// configured; callers should check before wiring routes.
func initOIDC(ctx context.Context, cfg OIDCConfig, log *zap.Logger) (*oidcRuntime, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" || cfg.SessionSecret == "" {
		return nil, nil
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %q: %w", cfg.IssuerURL, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = 8 * time.Hour
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = store.RoleViewer
	}
	log.Info("oidc enabled",
		zap.String("issuer", cfg.IssuerURL),
		zap.String("redirect", cfg.RedirectURL),
		zap.Duration("session_lifetime", cfg.SessionLifetime),
	)
	return &oidcRuntime{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
	}, nil
}

// handleOIDCLogin starts the authorization-code dance. A fresh state value
// is generated, stored in a short-lived cookie, and the user is redirected
// to the IdP authorize endpoint.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "oidc not configured")
		return
	}
	state, err := randomState()
	if err != nil {
		s.log.Error("oidc: random state", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, s.oidc.oauth2cfg.AuthCodeURL(state), http.StatusFound)
}

// handleOIDCCallback completes the dance: validates state, exchanges the
// authorisation code, verifies the ID token, derives the actor role from
// the configured claim mapping, and sets a signed session cookie.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "oidc not configured")
		return
	}
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" {
		writeError(w, http.StatusBadRequest, "missing state cookie")
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		writeError(w, http.StatusBadRequest, "state mismatch")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing authorization code")
		return
	}
	token, err := s.oidc.oauth2cfg.Exchange(r.Context(), code)
	if err != nil {
		s.log.Warn("oidc: token exchange", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "token exchange failed")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		writeError(w, http.StatusUnauthorized, "missing id_token in response")
		return
	}
	idToken, err := s.oidc.verifier.Verify(r.Context(), rawID)
	if err != nil {
		s.log.Warn("oidc: verify id_token", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "id_token invalid")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		writeError(w, http.StatusBadRequest, "decode claims failed")
		return
	}

	role := s.oidc.cfg.DefaultRole
	if claimMatch(claims, s.oidc.cfg.AdminClaim) {
		role = store.RoleAdmin
	} else if claimMatch(claims, s.oidc.cfg.OperatorClaim) {
		role = store.RoleOperator
	}
	subject := stringClaim(claims, "email")
	if subject == "" {
		subject = stringClaim(claims, "sub")
	}

	session := sessionPayload{
		Subject:   subject,
		Role:      role,
		ExpiresAt: time.Now().Add(s.oidc.cfg.SessionLifetime).Unix(),
	}
	cookieVal, err := encodeSession(session, s.oidc.cfg.SessionSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session encode failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(session.ExpiresAt, 0),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleOIDCLogout clears the session cookie and redirects home.
func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

// sessionPayload is the JSON blob signed and stored in the session cookie.
// The blob is base64url-encoded and concatenated with an HMAC-SHA256
// signature: "<base64-payload>.<base64-signature>".
type sessionPayload struct {
	// Subject is the user identifier (email when available, else sub).
	Subject string `json:"sub"`
	// Role is the effective Fleetsweeper role.
	Role string `json:"role"`
	// ExpiresAt is the unix timestamp at which the session lapses.
	ExpiresAt int64 `json:"exp"`
}

// encodeSession serializes and signs a session payload.
func encodeSession(p sessionPayload, secret string) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig, nil
}

// decodeSession verifies the signature and returns the payload. Returns an
// error when the signature is invalid, the payload is malformed, or the
// session has expired.
func decodeSession(cookie, secret string) (sessionPayload, error) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return sessionPayload{}, errors.New("malformed session cookie")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return sessionPayload{}, errors.New("session signature mismatch")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return sessionPayload{}, fmt.Errorf("decode payload: %w", err)
	}
	var p sessionPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return sessionPayload{}, fmt.Errorf("unmarshal payload: %w", err)
	}
	if p.ExpiresAt > 0 && time.Now().Unix() >= p.ExpiresAt {
		return sessionPayload{}, errors.New("session expired")
	}
	return p, nil
}

// claimMatch returns true when the configured "<claim>:<value>" pattern
// is present in the OIDC claims map. The claim value may be a string, a
// number, or a list of strings.
func claimMatch(claims map[string]any, pattern string) bool {
	if pattern == "" {
		return false
	}
	parts := strings.SplitN(pattern, ":", 2)
	if len(parts) != 2 {
		return false
	}
	name, want := parts[0], parts[1]
	v, ok := claims[name]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// stringClaim returns the named claim as a string, or empty if missing.
func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// randomState returns a fresh base64url-encoded 32-byte random value.
func randomState() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
