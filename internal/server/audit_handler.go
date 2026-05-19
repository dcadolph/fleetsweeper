package server

import (
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// handleAdminListAudit returns audit log entries newest first. Filters:
//   - ?limit=N (default 100)
//   - ?since=RFC3339 (only entries strictly after this time)
//   - ?actor=KEYID (only this actor)
//   - ?min_status=N (only responses with status >= N, e.g. 400 to see failures)
func (s *Server) handleAdminListAudit(w http.ResponseWriter, r *http.Request) {
	opts := store.AuditListOptions{}

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			opts.Limit = n
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.Since = t
		}
	}
	if v := r.URL.Query().Get("actor"); v != "" {
		opts.ActorID = v
	}
	if v := r.URL.Query().Get("min_status"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.MinStatus = n
		}
	}

	entries, err := s.store.ListAuditEntries(r.Context(), opts)
	if err != nil {
		s.log.Error("admin audit: list", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list audit failed")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// whoamiResponse describes the effective identity of the calling actor. The UI
// uses it to render available controls and hide actions the caller cannot perform.
type whoamiResponse struct {
	// ID is the API key identifier (or "bootstrap"/"anonymous").
	ID string `json:"id"`
	// Name is the human-readable label.
	Name string `json:"name,omitempty"`
	// Role is the effective role.
	Role string `json:"role"`
	// ClusterScope is the cluster scope this actor was minted with.
	ClusterScope []string `json:"cluster_scope"`
}

// handleAdminWhoami returns the effective identity of the calling actor.
// It lives under /admin/ so it doubles as a quick "is my token admin?" probe,
// but viewers/operators can reach it too via their own /whoami once added.
// For now the admin gate is acceptable since only admin keys typically need
// to introspect their effective scope from the dashboard.
func (s *Server) handleAdminWhoami(w http.ResponseWriter, r *http.Request) {
	a := actorFromContext(r.Context())
	writeJSON(w, http.StatusOK, whoamiResponse{
		ID:           a.ID,
		Name:         a.Name,
		Role:         a.Role,
		ClusterScope: a.ClusterScope,
	})
}
