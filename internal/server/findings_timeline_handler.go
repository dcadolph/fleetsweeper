package server

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Default and maximum number of scans a drift-replay or persistence request
// rebuilds, bounding the report work done per request.
const (
	replayDefaultScans = 24
	replayMaxScans     = 60
)

// timelineFinding is the light finding identity carried in a timeline point. It
// omits the report's heavy fields (description, remediation) so a whole window
// of scans transfers in one response.
type timelineFinding struct {
	// Fingerprint is the stable finding identifier, matching its ack key.
	Fingerprint string `json:"fingerprint"`
	// Title is the finding title.
	Title string `json:"title"`
	// Severity is critical, warning, or info.
	Severity string `json:"severity"`
	// Cluster is the finding's cluster scope, or "fleet".
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produced the finding.
	Scanner string `json:"scanner"`
}

// timelinePoint is the fleet findings at a single scan in the replay window.
type timelinePoint struct {
	// ScanID is the scan this point was computed from.
	ScanID string `json:"scan_id"`
	// Timestamp is the scan time in RFC3339.
	Timestamp string `json:"timestamp"`
	// Total is the number of findings in the scan.
	Total int `json:"total"`
	// Critical, Warning, and Info are per-severity counts.
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	// Findings are the light finding identities present in the scan.
	Findings []timelineFinding `json:"findings"`
}

// handleFindingsTimeline returns the fleet findings for the most recent scans,
// oldest first, so the dashboard can replay how findings appeared and resolved
// over time. Each point carries only light finding identity fields.
func (s *Server) handleFindingsTimeline(w http.ResponseWriter, r *http.Request) {
	n := clampScanWindow(r, replayDefaultScans, replayMaxScans)
	series, err := s.findingSeries(r.Context(), n)
	if err != nil {
		s.log.Error("findings timeline", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "findings timeline failed")
		return
	}

	points := make([]timelinePoint, len(series))
	for i, sf := range series {
		fs := make([]timelineFinding, len(sf.Findings))
		var crit, warn, info int
		for j, f := range sf.Findings {
			fs[j] = timelineFinding{
				Fingerprint: util.Fingerprint(f.Cluster, f.Scanner, f.Title),
				Title:       f.Title,
				Severity:    f.Severity,
				Cluster:     f.Cluster,
				Scanner:     f.Scanner,
			}
			switch f.Severity {
			case report.SeverityCritical:
				crit++
			case report.SeverityWarning:
				warn++
			default:
				info++
			}
		}
		points[i] = timelinePoint{
			ScanID:    sf.ScanID,
			Timestamp: sf.Timestamp.UTC().Format(time.RFC3339),
			Total:     len(fs),
			Critical:  crit,
			Warning:   warn,
			Info:      info,
			Findings:  fs,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"scans": len(points), "points": points})
}

// handleFindingsPersistence classifies each finding by how often it recurred
// across the recent scan window, an implicit learned-severity signal, and marks
// which findings carry an active acknowledgement.
func (s *Server) handleFindingsPersistence(w http.ResponseWriter, r *http.Request) {
	n := clampScanWindow(r, replayDefaultScans, replayMaxScans)
	series, err := s.findingSeries(r.Context(), n)
	if err != nil {
		s.log.Error("findings persistence", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "findings persistence failed")
		return
	}

	sets := make([][]report.Finding, len(series))
	for i, sf := range series {
		sets[i] = sf.Findings
	}
	ps := report.ComputePersistence(sets, s.ackedFingerprints(r.Context()))

	var chronic, intermittent, transient int
	for _, p := range ps {
		switch p.Class {
		case report.PersistenceChronic:
			chronic++
		case report.PersistenceIntermittent:
			intermittent++
		default:
			transient++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"scans":        len(series),
		"chronic":      chronic,
		"intermittent": intermittent,
		"transient":    transient,
		"findings":     ps,
	})
}
