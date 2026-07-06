package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// createAPIKeyRequest is the JSON body for POST /api/admin/keys.
type createAPIKeyRequest struct {
	// Name is a human-readable label for the key (required).
	Name string `json:"name"`
	// Role is one of admin, operator, viewer (required).
	Role string `json:"role"`
	// ClusterScope is the list of cluster names (or "group:<name>" entries)
	// this key may act on. Empty defaults to ["*"].
	ClusterScope []string `json:"cluster_scope"`
	// TTL, when non-zero, sets an expiry duration as an RFC3339 duration string
	// (for example "720h" for 30 days). Empty means no expiry.
	TTL string `json:"ttl"`
}

// createAPIKeyResponse returns the freshly minted token. The raw token is
// shown exactly once: callers must capture it now or revoke and recreate.
type createAPIKeyResponse struct {
	// Key is the metadata, never including the raw token.
	Key store.APIKeyRecord `json:"key"`
	// Token is the raw bearer token. Save it now; it cannot be retrieved later.
	Token string `json:"token"`
}

// handleAdminCreateKey mints a new API key under the calling admin's authority.
func (s *Server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !store.ValidRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin, operator, or viewer")
		return
	}

	raw, err := store.GenerateToken()
	if err != nil {
		s.log.Error("admin keys: generate token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "generate token failed")
		return
	}

	rec := store.APIKeyRecord{
		ID:           newKeyID(),
		TokenHash:    store.HashToken(raw),
		Name:         req.Name,
		Role:         req.Role,
		ClusterScope: normalizeScope(req.ClusterScope),
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    actorFromContext(r.Context()).ID,
	}
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "ttl must be a Go duration (for example 720h)")
			return
		}
		rec.ExpiresAt = rec.CreatedAt.Add(d)
	}

	if err := s.store.SaveAPIKey(r.Context(), rec); err != nil {
		s.log.Error("admin keys: save", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "save key failed")
		return
	}

	writeJSON(w, http.StatusCreated, createAPIKeyResponse{Key: rec, Token: raw})
}

// handleAdminListKeys returns every API key, newest first. Token hashes are
// never returned; the raw token is unavailable after creation.
func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys(r.Context())
	if err != nil {
		s.log.Error("admin keys: list", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list keys failed")
		return
	}
	out := make([]store.APIKeyRecord, len(keys))
	for i, k := range keys {
		k.TokenHash = ""
		out[i] = k
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAdminRevokeKey marks the key with the path ID as administratively
// disabled. Idempotent: revoking an already-revoked key returns 204.
func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "key id required")
		return
	}
	if err := s.store.RevokeAPIKey(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		s.log.Error("admin keys: revoke", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "revoke key failed")
		return
	}
	s.PublishEvent(EventKeyRevoked, map[string]any{
		"key_id":     id,
		"revoked_by": actorFromContext(r.Context()).ID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// normalizeScope cleans up a user-supplied scope list: empty becomes wildcard,
// duplicates are removed, and entries are kept in input order so the original
// intent is preserved when listing keys back.
func normalizeScope(in []string) []string {
	if len(in) == 0 {
		return []string{store.ScopeWildcard}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return []string{store.ScopeWildcard}
	}
	return out
}

// newKeyID returns an opaque, time-sortable identifier for an API key. We
// reuse the store package's generator by going through a fresh record.
func newKeyID() string {
	return "key_" + shortID()
}

// shortID returns a short, URL-safe random identifier suitable for key ids and
// other administratively-visible identifiers. The leading time component keeps
// ordering stable while admins paginate.
func shortID() string {
	now := time.Now().UnixMilli()
	raw, _ := store.GenerateToken()
	if len(raw) < 12 {
		return formatHex(now)
	}
	return formatHex(now) + "-" + raw[4:12]
}

// formatHex renders a uint64 millisecond timestamp as a fixed-width hex string
// so identifiers sort lexicographically.
func formatHex(ms int64) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 12)
	for i := 11; i >= 0; i-- {
		out[i] = hexdigits[ms&0xf]
		ms >>= 4
	}
	return string(out)
}
