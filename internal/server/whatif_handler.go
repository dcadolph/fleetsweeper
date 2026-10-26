package server

import (
	"errors"
	"net/http"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// whatifRequest is the body of POST /api/whatif.
type whatifRequest struct {
	// Cluster is the cluster to fix.
	Cluster string `json:"cluster"`
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field to fix, as distributions name it.
	Field string `json:"field"`
	// Fix is the fix kind: median, mode, consensus, or remove. Empty picks the one that fits.
	Fix string `json:"fix,omitempty"`
	// Scope is "fleet" or a cohort name. Empty means fleet.
	Scope string `json:"scope,omitempty"`
	// Scan is the scan to project from. Empty means the latest.
	Scan string `json:"scan,omitempty"`
}

// whatifResponse is the body returned by POST /api/whatif.
type whatifResponse struct {
	// ScanID is the scan the projection started from.
	ScanID string `json:"scan_id"`
	// Outcome is the projected score and norm movement.
	Outcome report.Outcome `json:"outcome"`
}

// handleWhatIf projects how the score and the field's norm move if one cluster's field were
// fixed. It rebuilds the scan from a patched copy of its results and writes nothing, so a
// read-scope key may call it, but it draws on the write rate limit because each call rebuilds
// two reports. A cluster outside the caller's scope is a 403.
func (s *Server) handleWhatIf(w http.ResponseWriter, r *http.Request) {
	var req whatifRequest
	if err := decodeJSON(w, r, &req, maxJSONBody); err != nil {
		return
	}
	if req.Cluster == "" || req.Scanner == "" || req.Field == "" {
		writeError(w, http.StatusBadRequest, "cluster, scanner, and field are required")
		return
	}
	if a := actorFromContext(r.Context()); !a.AllowsCluster(req.Cluster, s.groupLookup(r.Context())) {
		writeError(w, http.StatusForbidden, "cluster outside actor scope")
		return
	}
	if req.Scan != "" {
		q := r.URL.Query()
		q.Set("scan", req.Scan)
		r.URL.RawQuery = q.Encode()
	}
	in, ok := s.loadScanInput(w, r, "whatif")
	if !ok {
		return
	}
	fix := report.Fix{Cluster: req.Cluster, Scanner: req.Scanner, Field: req.Field, Kind: req.Fix, Scope: req.Scope}
	out, err := report.WhatIf(in.Clusters, in.Results, in.Opts, fix)
	if errors.Is(err, report.ErrWhatIf) {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		s.log.Error("whatif")
		writeError(w, http.StatusInternalServerError, "whatif failed")
		return
	}
	writeJSON(w, http.StatusOK, whatifResponse{ScanID: in.ID, Outcome: out})
}
