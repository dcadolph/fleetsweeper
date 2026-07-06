package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// Actor describes who is performing a request after authentication.
// An Actor is always present once authMiddleware has run, even in --insecure
// mode where it represents an anonymous admin.
type Actor struct {
	// ID is the API key identifier, or "bootstrap" for --auth-token, or
	// "anonymous" for --insecure mode.
	ID string
	// Name is a human-readable label for log lines and audit entries.
	Name string
	// Role is one of store.RoleAdmin, store.RoleOperator, store.RoleViewer.
	Role string
	// ClusterScope is the list of cluster names (or "group:<n>" entries) this
	// actor may act upon. The single element "*" grants unrestricted access.
	ClusterScope []string
}

// HasWildcardScope reports whether the actor may act on any cluster.
func (a *Actor) HasWildcardScope() bool {
	return slices.Contains(a.ClusterScope, store.ScopeWildcard)
}

// AllowsCluster reports whether the actor may act on the given cluster.
// groupLookup, when non-nil, resolves "group:<name>" scope entries to their
// member cluster names so a group-scoped key authorises any current member.
func (a *Actor) AllowsCluster(cluster string, groupLookup func(name string) []string) bool {
	if a.HasWildcardScope() {
		return true
	}
	for _, entry := range a.ClusterScope {
		if entry == cluster {
			return true
		}
		if groupLookup != nil && strings.HasPrefix(entry, "group:") {
			groupName := strings.TrimPrefix(entry, "group:")
			if slices.Contains(groupLookup(groupName), cluster) {
				return true
			}
		}
	}
	return false
}

// FilterClusters returns the subset of clusters the actor is permitted to act on.
func (a *Actor) FilterClusters(clusters []string, groupLookup func(name string) []string) []string {
	if a.HasWildcardScope() {
		return clusters
	}
	out := make([]string, 0, len(clusters))
	for _, c := range clusters {
		if a.AllowsCluster(c, groupLookup) {
			out = append(out, c)
		}
	}
	return out
}

// actorCtxKey is the context key under which the resolved Actor is stored.
type actorCtxKey struct{}

// withActor returns a child context carrying the actor. Handlers that need
// the actor should call actorFromContext instead of touching the context directly.
func withActor(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

// actorFromContext returns the resolved Actor or a deny-all default when
// authentication did not run (defense in depth; should not happen in practice).
func actorFromContext(ctx context.Context) *Actor {
	if a, ok := ctx.Value(actorCtxKey{}).(*Actor); ok && a != nil {
		return a
	}
	return &Actor{ID: "unknown", Role: store.RoleViewer}
}

// roleAllowsWrite reports whether the role may perform mutating operations
// outside the admin namespace.
func roleAllowsWrite(role string) bool {
	return role == store.RoleAdmin || role == store.RoleOperator
}

// authMiddleware resolves the request actor and attaches it to the context.
// It enforces token presence for mutating endpoints but does not check scope:
// scope is enforced per handler since it depends on which cluster is targeted.
//
// Resolution order:
//  1. --insecure mode → anonymous admin
//  2. Bearer matches bootstrap --auth-token → built-in admin
//  3. Bearer matches an api_keys row → that key
//  4. Otherwise: 401 on mutating requests, anonymous viewer on reads
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /webhooks/* endpoints carry their own request authentication
		// (HMAC signature for scan-trigger, bearer-secret comparison for
		// alertmanager). Skip the bearer check so external systems can
		// reach the handlers without holding a Fleetsweeper API key.
		if pathIsWebhook(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		actor, err := s.resolveActor(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		if requiresWrite(r) {
			if actor.ID == "" {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			if !roleAllowsWrite(actor.Role) && !pathIsAdmin(r.URL.Path) {
				writeError(w, http.StatusForbidden, "role does not permit writes")
				return
			}
		}
		if pathIsAdmin(r.URL.Path) {
			if actor.ID == "" || actor.Role != store.RoleAdmin {
				writeError(w, http.StatusForbidden, "admin role required")
				return
			}
		}

		r = r.WithContext(withActor(r.Context(), actor))
		next.ServeHTTP(w, r)
	})
}

// pathIsWebhook reports whether the request path targets an inbound
// webhook handler that authenticates the call body itself.
func pathIsWebhook(path string) bool {
	return strings.HasPrefix(path, "/webhooks/")
}

// resolveActor inspects the request and the server config to produce an Actor.
// A nil Actor with a nil error means an anonymous viewer (used for read-only
// requests in non-insecure mode without a token).
func (s *Server) resolveActor(r *http.Request) (*Actor, error) {
	if s.insecure {
		return &Actor{
			ID:           "anonymous",
			Name:         "insecure-mode",
			Role:         store.RoleAdmin,
			ClusterScope: []string{store.ScopeWildcard},
		}, nil
	}

	raw := extractBearer(r.Header.Get("Authorization"))
	if raw == "" {
		if actor := s.actorFromSessionCookie(r); actor != nil {
			return actor, nil
		}
		return &Actor{Role: store.RoleViewer}, nil
	}

	if s.authToken != "" && store.TokensEqual(raw, s.authToken) {
		return &Actor{
			ID:           "bootstrap",
			Name:         "bootstrap-token",
			Role:         store.RoleAdmin,
			ClusterScope: []string{store.ScopeWildcard},
		}, nil
	}

	hash := store.HashToken(raw)
	rec, err := s.store.GetAPIKeyByHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("invalid bearer token")
		}
		s.log.Warn("auth: lookup failed", zap.Error(err))
		return nil, errors.New("authentication unavailable")
	}
	if !rec.RevokedAt.IsZero() {
		return nil, errors.New("token revoked")
	}
	if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
		return nil, errors.New("token expired")
	}
	s.bg.Add(1)
	go func(id string) {
		defer s.bg.Done()
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
		defer cancel()
		if err := s.store.TouchAPIKey(ctx, id, time.Now().UTC()); err != nil {
			s.log.Debug("auth: touch failed", zap.Error(err))
		}
	}(rec.ID)

	return &Actor{
		ID:           rec.ID,
		Name:         rec.Name,
		Role:         rec.Role,
		ClusterScope: rec.ClusterScope,
	}, nil
}

// actorFromSessionCookie resolves the OIDC session cookie when present.
// Returns nil when OIDC is not configured, the cookie is missing, or the
// cookie fails signature/expiry validation.
func (s *Server) actorFromSessionCookie(r *http.Request) *Actor {
	if s.oidc == nil {
		return nil
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	session, err := decodeSession(cookie.Value, s.oidc.cfg.SessionSecret)
	if err != nil {
		return nil
	}
	role := session.Role
	if !store.ValidRole(role) {
		role = store.RoleViewer
	}
	name := session.Subject
	if name == "" {
		name = "oidc-session"
	}
	return &Actor{
		ID:           "oidc:" + session.Subject,
		Name:         name,
		Role:         role,
		ClusterScope: []string{store.ScopeWildcard},
	}
}

// extractBearer pulls the raw token from an Authorization header value.
// Returns "" when the header is missing or malformed.
func extractBearer(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// requiresWrite reports whether the request method mutates state. CONNECT and
// TRACE are not used by Fleetsweeper but are deliberately treated as writes so
// any future routing change defaults to "secured by default."
func requiresWrite(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// pathIsAdmin reports whether the request path is one of the admin-only
// endpoints. Admin endpoints require role=admin even for GETs.
func pathIsAdmin(path string) bool {
	return strings.HasPrefix(path, "/admin/")
}

// groupLookup returns a function that resolves a group name to its current
// member clusters by consulting the store. The closure is intended for use
// with Actor.AllowsCluster and similar helpers.
func (s *Server) groupLookup(ctx context.Context) func(string) []string {
	return func(name string) []string {
		g, err := s.store.GetGroup(ctx, name)
		if err != nil || g == nil {
			return nil
		}
		return g.Clusters
	}
}
