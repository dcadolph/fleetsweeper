package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// ackRequest is the optional JSON body for POST /api/findings/{fingerprint}/ack
// and POST /api/alerts/{fingerprint}/ack. The server takes cluster, scanner, and
// title from the finding or alert it holds, so the client supplies only the
// human context.
type ackRequest struct {
	// AckBy identifies the operator. Optional, free-form.
	AckBy string `json:"ack_by"`
	// Reason is the operator's stated reason. Optional, free-form.
	Reason string `json:"reason"`
	// SnoozeUntil, when set, is an RFC3339 timestamp at which the ack
	// expires. Omit for a permanent ack.
	SnoozeUntil string `json:"snooze_until,omitempty"`
}

// handleListAcks returns every active acknowledgement.
func (s *Server) handleListAcks(w http.ResponseWriter, r *http.Request) {
	acks, err := s.store.ListAcks(r.Context())
	if err != nil {
		s.log.Warn("acks: list", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list acks failed")
		return
	}
	writeJSON(w, http.StatusOK, acks)
}

// handleCreateAck records (or refreshes) an acknowledgement for the finding
// identified by the fingerprint in the URL path. The fingerprint is the
// finding's served fingerprint field, the SHA-256 of cluster|scanner|rule, so
// the ack keeps matching when a count in the finding's title changes. The
// finding must be in the latest report: its cluster decides the scope check
// and its cluster, scanner, and title are what the ack stores.
func (s *Server) handleCreateAck(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	f, err := s.currentFinding(r.Context(), fp)
	if err != nil {
		s.writeStoreError(w, err, "acks: find finding", "no current finding has this fingerprint")
		return
	}
	if !s.allowsAckCluster(r.Context(), f.Cluster) {
		writeError(w, http.StatusForbidden, "finding cluster not in actor scope")
		return
	}
	s.saveAck(w, r, store.AckRecord{
		Fingerprint: fp,
		Cluster:     f.Cluster,
		Scanner:     f.Scanner,
		Title:       f.Title,
	})
}

// handleAckAlert records an ack against an inbound alert. The alert
// row is fetched by fingerprint so the cluster, title, and source tag
// don't have to be re-supplied by the client. The same `finding_acks`
// table is reused: alerts share the snooze and tombstone machinery with
// scan findings so the dashboard surfaces them uniformly.
func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	alert, err := s.store.GetAlert(r.Context(), fp)
	if err != nil {
		s.writeStoreError(w, err, "acks: get alert", "alert not found")
		return
	}
	if alert.Cluster != "" {
		if !actorFromContext(r.Context()).AllowsCluster(alert.Cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "alert cluster not in actor scope")
			return
		}
	}
	s.saveAck(w, r, store.AckRecord{
		Fingerprint: fp,
		Cluster:     alert.Cluster,
		Scanner:     "alert:" + firstNonEmpty(alert.Labels["source"], "alertmanager"),
		Title:       alert.AlertName,
	})
}

// handleDeleteAck removes the acknowledgement for the given fingerprint. The
// scope check reads the cluster stored on the ack row. Idempotent: a missing
// row returns 204 just like a successful delete.
func (s *Server) handleDeleteAck(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	rec, err := s.store.GetAck(r.Context(), fp)
	switch {
	case errors.Is(err, store.ErrNotFound):
		w.WriteHeader(http.StatusNoContent)
		return
	case err != nil:
		s.log.Warn("acks: get", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get ack failed")
		return
	}
	if !s.allowsAckCluster(r.Context(), rec.Cluster) {
		writeError(w, http.StatusForbidden, "ack cluster not in actor scope")
		return
	}
	if err := s.store.DeleteAck(r.Context(), fp); err != nil {
		s.log.Warn("acks: delete", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "delete ack failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// currentFinding returns the finding in the latest report whose fingerprint is
// fp. Returns store.ErrNotFound when no scan exists or no finding carries it.
func (s *Server) currentFinding(ctx context.Context, fp string) (report.Finding, error) {
	rpt, err := s.latestReport(ctx)
	if err != nil {
		return report.Finding{}, err
	}
	if rpt != nil {
		for _, f := range rpt.Findings {
			if f.Fingerprint == fp {
				return f, nil
			}
		}
	}
	return report.Finding{}, store.ErrNotFound
}

// allowsAckCluster reports whether the request's actor may change an ack on
// cluster. A fleet-scoped or cluster-less ack spans every cluster, so it needs
// wildcard scope.
func (s *Server) allowsAckCluster(ctx context.Context, cluster string) bool {
	actor := actorFromContext(ctx)
	if cluster == "" || cluster == "fleet" {
		return actor.HasWildcardScope()
	}
	return actor.AllowsCluster(cluster, s.groupLookup(ctx))
}

// saveAck decodes the optional ack body into base, persists the record, and
// writes it back with 201. The caller fills base from a server-owned object and
// checks scope first, so the body cannot change what the ack covers.
func (s *Server) saveAck(w http.ResponseWriter, r *http.Request, base store.AckRecord) {
	var req ackRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &req, maxJSONBody); err != nil {
			return
		}
	}
	base.AckBy = req.AckBy
	base.Reason = req.Reason
	base.CreatedAt = time.Now().UTC()
	if req.SnoozeUntil != "" {
		t, err := time.Parse(time.RFC3339, req.SnoozeUntil)
		if err != nil {
			writeError(w, http.StatusBadRequest, "snooze_until must be RFC3339")
			return
		}
		base.SnoozeUntil = t
	}
	if err := s.store.SaveAck(r.Context(), base); err != nil {
		s.log.Warn("acks: save", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "save ack failed")
		return
	}
	writeJSON(w, http.StatusCreated, base)
}
