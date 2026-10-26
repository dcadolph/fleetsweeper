package server

import (
	"net/http"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// cohortMapResponse is the body of GET /api/cohorts/map.
type cohortMapResponse struct {
	// ScanID is the scan the map came from.
	ScanID string `json:"scan_id"`
	// Map is the two-dimensional layout of the fleet with peers and leaf order.
	Map cohort.Map `json:"map"`
}

// handleGetCohortMap returns the cohort map of one scan: each cluster's position from classical
// scaling of the cohort feature vectors, its cohort, its nearest peers, and a leaf order that
// keeps cohorts contiguous.
func (s *Server) handleGetCohortMap(w http.ResponseWriter, r *http.Request) {
	in, ok := s.loadScanInput(w, r, "cohort map")
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, cohortMapResponse{ScanID: in.ID, Map: report.CohortMapFor(in.build())})
}
