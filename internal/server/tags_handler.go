package server

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// tagRequest is the JSON body for PUT /api/clusters/{name}/tags/{key}.
type tagRequest struct {
	// Value is the tag's string value. Empty values are accepted (they
	// just disambiguate a tag from absence).
	Value string `json:"value"`
}

// handleSetClusterTag upserts one tag key/value pair on a cluster.
func (s *Server) handleSetClusterTag(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	key := r.PathValue("key")
	if cluster == "" || key == "" {
		writeError(w, http.StatusBadRequest, "cluster and key required")
		return
	}
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		if !a.AllowsCluster(cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "cluster outside actor scope")
			return
		}
	}
	var req tagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.SetClusterTag(r.Context(), cluster, key, req.Value); err != nil {
		s.log.Warn("tags: set", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "set tag failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{key: req.Value})
}

// handleDeleteClusterTag removes one tag key from a cluster.
func (s *Server) handleDeleteClusterTag(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	key := r.PathValue("key")
	if cluster == "" || key == "" {
		writeError(w, http.StatusBadRequest, "cluster and key required")
		return
	}
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		if !a.AllowsCluster(cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "cluster outside actor scope")
			return
		}
	}
	if err := s.store.DeleteClusterTag(r.Context(), cluster, key); err != nil {
		s.log.Warn("tags: delete", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "delete tag failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListClusterTags returns every tag on a single cluster.
func (s *Server) handleListClusterTags(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	if cluster == "" {
		writeError(w, http.StatusBadRequest, "cluster required")
		return
	}
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		if !a.AllowsCluster(cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "cluster outside actor scope")
			return
		}
	}
	tags, err := s.store.GetClusterTags(r.Context(), cluster)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get tags failed")
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

// handleListAllTags returns every cluster's tags, grouped by cluster
// name. Used by the dashboard to render tag chips next to each cluster
// without an N+1 fetch.
func (s *Server) handleListAllTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.store.ListClusterTags(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list tags failed")
		return
	}
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		filtered := make(map[string]map[string]string, len(tags))
		for cluster, m := range tags {
			if a.AllowsCluster(cluster, s.groupLookup(r.Context())) {
				filtered[cluster] = m
			}
		}
		tags = filtered
	}
	writeJSON(w, http.StatusOK, tags)
}
