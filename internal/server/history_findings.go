package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// scanFindings is the fleet findings for a single scan and when that scan ran.
// A slice of these, ordered oldest to newest, is the shared input for drift
// replay and finding persistence.
type scanFindings struct {
	// ScanID is the scan the findings were computed from.
	ScanID string
	// Timestamp is when the scan ran.
	Timestamp time.Time
	// Findings are the findings the report engine produced for that scan.
	Findings []report.Finding
}

// findingSeries rebuilds the fleet findings for the most recent n scans, oldest
// first, so callers can measure how findings appear, resolve, and recur over
// time. In demo mode it returns a synthesized series; otherwise it rebuilds each
// stored scan through the real report engine.
func (s *Server) findingSeries(ctx context.Context, n int) ([]scanFindings, error) {
	if s.demo {
		return demoFindingSeries(n), nil
	}

	scans, err := s.store.ListScans(ctx, n)
	if err != nil {
		return nil, err
	}

	out := make([]scanFindings, 0, len(scans))
	// ListScans returns newest first; walk it in reverse for oldest to newest.
	for i := len(scans) - 1; i >= 0; i-- {
		sc := scans[i]
		results, err := s.store.GetScanResults(ctx, sc.ID)
		if err != nil {
			s.log.Warn("finding series: get scan results", zap.String("scan", sc.ID), zap.Error(err))
			continue
		}
		rpt := report.Build(sc.Clusters, results)
		out = append(out, scanFindings{ScanID: sc.ID, Timestamp: sc.Timestamp, Findings: rpt.Findings})
	}
	return out, nil
}

// ackedFingerprints returns the set of finding fingerprints with an active
// acknowledgement. A store error is logged and treated as no acks so the caller
// still returns persistence data.
func (s *Server) ackedFingerprints(ctx context.Context) map[string]bool {
	acks, err := s.store.ListAcks(ctx)
	if err != nil {
		s.log.Warn("finding persistence: list acks", zap.Error(err))
		return nil
	}
	set := make(map[string]bool, len(acks))
	for _, a := range acks {
		set[a.Fingerprint] = true
	}
	return set
}

// clampScanWindow reads the scans query parameter, applying a default and an
// upper bound so one request cannot rebuild an unbounded number of reports.
func clampScanWindow(r *http.Request, def, max int) int {
	n := def
	if v := r.URL.Query().Get("scans"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > max {
		n = max
	}
	return n
}
