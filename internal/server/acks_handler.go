package server

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// ackRequest is the JSON body for POST /api/findings/{fingerprint}/ack.
type ackRequest struct {
	// Cluster echoes the finding's cluster scope. Optional; helps when
	// listing acks back.
	Cluster string `json:"cluster"`
	// Scanner echoes the finding's source scanner. Optional.
	Scanner string `json:"scanner"`
	// Title echoes the finding's title at ack time. Optional but recommended.
	Title string `json:"title"`
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
// SHA-256 of cluster|scanner|title; the server does not compute it because
// clients usually have the finding object already and can derive it locally.
func (s *Server) handleCreateAck(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	var req ackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Cluster != "" && req.Cluster != "fleet" {
		if !actorFromContext(r.Context()).AllowsCluster(req.Cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "cluster not in actor scope")
			return
		}
	}
	rec := store.AckRecord{
		Fingerprint: fp,
		Cluster:     req.Cluster,
		Scanner:     req.Scanner,
		Title:       req.Title,
		AckBy:       req.AckBy,
		Reason:      req.Reason,
		CreatedAt:   time.Now().UTC(),
	}
	if req.SnoozeUntil != "" {
		t, err := time.Parse(time.RFC3339, req.SnoozeUntil)
		if err != nil {
			writeError(w, http.StatusBadRequest, "snooze_until must be RFC3339")
			return
		}
		rec.SnoozeUntil = t
	}
	if err := s.store.SaveAck(r.Context(), rec); err != nil {
		s.log.Warn("acks: save", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "save ack failed")
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

// alertAckRequest is the smaller body the alert-ack endpoint takes —
// the cluster/title/scanner fields are derived server-side from the
// alert row so the client only supplies the human-supplied context.
type alertAckRequest struct {
	// AckBy identifies the operator. Optional, free-form.
	AckBy string `json:"ack_by"`
	// Reason is the operator's stated reason. Optional, free-form.
	Reason string `json:"reason"`
	// SnoozeUntil, when set, is an RFC3339 timestamp at which the ack
	// expires. Omit for a permanent ack.
	SnoozeUntil string `json:"snooze_until,omitempty"`
}

// handleAckAlert records an ack against an inbound alert. The alert
// row is fetched by fingerprint so the cluster, title, and source tag
// don't have to be re-supplied by the client. The same `finding_acks`
// table is reused — alerts share the snooze + tombstone machinery with
// scan findings so the dashboard surfaces them uniformly.
func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	alert, err := s.store.GetAlert(r.Context(), fp)
	if err != nil {
		writeError(w, http.StatusNotFound, "alert not found: "+err.Error())
		return
	}
	if alert.Cluster != "" {
		if !actorFromContext(r.Context()).AllowsCluster(alert.Cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "alert cluster not in actor scope")
			return
		}
	}
	var req alertAckRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	rec := store.AckRecord{
		Fingerprint: fp,
		Cluster:     alert.Cluster,
		Scanner:     "alert:" + firstNonEmpty(alert.Labels["source"], "alertmanager"),
		Title:       alert.AlertName,
		AckBy:       req.AckBy,
		Reason:      req.Reason,
		CreatedAt:   time.Now().UTC(),
	}
	if req.SnoozeUntil != "" {
		t, err := time.Parse(time.RFC3339, req.SnoozeUntil)
		if err != nil {
			writeError(w, http.StatusBadRequest, "snooze_until must be RFC3339")
			return
		}
		rec.SnoozeUntil = t
	}
	if err := s.store.SaveAck(r.Context(), rec); err != nil {
		s.log.Warn("acks: alert save", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "save ack failed")
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

// handleDeleteAck removes the acknowledgement for the given fingerprint.
// Idempotent: a missing row returns 204 just like a successful delete.
func (s *Server) handleDeleteAck(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	if err := s.store.DeleteAck(r.Context(), fp); err != nil {
		s.log.Warn("acks: delete", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "delete ack failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
