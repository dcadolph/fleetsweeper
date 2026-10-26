package server

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// maxHistoryScans caps how many scans a history or drift request rebuilds.
const maxHistoryScans = 50

// scanInput is everything needed to rebuild one scan's report: the scan, its
// results, and the build options the server applies.
type scanInput struct {
	// ID is the scan ID.
	ID string
	// Timestamp is when the scan ran.
	Timestamp time.Time
	// Clusters lists the scanned clusters.
	Clusters []string
	// Results holds the per-cluster scanner results.
	Results map[string]map[string]scanner.Result
	// Opts are the build options, with Timestamp set to the scan time.
	Opts report.BuildOptions
	// Cache, when set, holds reports already rebuilt for this scan and options.
	Cache *reportCache
}

// build returns the report for the scan, from the cache when one is set. The report may be
// shared, so callers read it and copy anything they change.
func (in *scanInput) build() *report.Report {
	if in.Cache != nil {
		return in.Cache.get(in.ID, in.Clusters, in.Results, in.Opts)
	}
	return report.Build(in.Clusters, in.Results, in.Opts)
}

// loadScanInput returns the scan a read endpoint reports on, chosen by ?scan= or else the
// latest, with its results and the server's build options. It writes the error response and
// returns ok=false on failure, including a 404 when there is no scan at all.
func (s *Server) loadScanInput(w http.ResponseWriter, r *http.Request, op string) (*scanInput, bool) {
	latest, ok := s.latestScan(w, r, op)
	if !ok {
		return nil, false
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no scans available")
		return nil, false
	}
	return s.scanInputFor(w, r, *latest, op)
}

// scanInputFor loads the results of rec and pairs them with the server's build options.
func (s *Server) scanInputFor(w http.ResponseWriter, r *http.Request, rec store.ScanRecord, op string) (*scanInput, bool) {
	return s.scanInputWith(w, r, rec, s.reportOptions(r.Context(), s.log), op)
}

// scanInputWith loads the results of rec, one store round trip, and pairs them with opts stamped
// with the scan time. Series reuse one opts so each extra scan costs a single read.
func (s *Server) scanInputWith(w http.ResponseWriter, r *http.Request, rec store.ScanRecord, opts report.BuildOptions,
	op string) (*scanInput, bool) {
	results, err := s.store.GetScanResults(r.Context(), rec.ID)
	if err != nil {
		s.writeStoreError(w, err, op+": get scan results", "scan results not found")
		return nil, false
	}
	opts.Timestamp = rec.Timestamp
	return &scanInput{ID: rec.ID, Timestamp: rec.Timestamp, Clusters: rec.Clusters, Results: results, Opts: opts, Cache: &s.reports}, true
}

// loadScanSeries returns up to n of the most recent scans, oldest first, ready to rebuild. It
// writes the error response and returns ok=false on failure.
func (s *Server) loadScanSeries(w http.ResponseWriter, r *http.Request, n int, op string) ([]*scanInput, bool) {
	scans, err := s.store.ListScans(r.Context(), n)
	if err != nil {
		s.writeStoreError(w, err, op+": list scans", "no scans available")
		return nil, false
	}
	opts := s.reportOptions(r.Context(), s.log)
	out := make([]*scanInput, 0, len(scans))
	for i := len(scans) - 1; i >= 0; i-- {
		in, ok := s.scanInputWith(w, r, scans[i], opts, op)
		if !ok {
			return nil, false
		}
		out = append(out, in)
	}
	return out, true
}

// distributionsResponse is the body of GET /api/distributions.
type distributionsResponse struct {
	// ScanID is the scan the distributions came from.
	ScanID string `json:"scan_id"`
	// Distributions are the matching distributions, most deviant first.
	Distributions []report.Distribution `json:"distributions"`
}

// handleGetDistributions returns the distributions behind the fleet norm for one scan, filtered
// by scope (default fleet, "*" for every scope), scanner, and field, most deviant first.
func (s *Server) handleGetDistributions(w http.ResponseWriter, r *http.Request) {
	in, ok := s.loadScanInput(w, r, "distributions")
	if !ok {
		return
	}
	q := r.URL.Query()
	scope := q.Get("scope")
	if scope == "" {
		scope = report.NormScopeFleet
	}
	out := distributionsResponse{ScanID: in.ID, Distributions: []report.Distribution{}}
	for _, d := range in.build().Distributions {
		if scope != "*" && d.Scope != scope {
			continue
		}
		if v := q.Get("scanner"); v != "" && d.Scanner != v {
			continue
		}
		if v := q.Get("field"); v != "" && d.Field != v {
			continue
		}
		out.Distributions = append(out.Distributions, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// historyPoint is one scan's distribution of a field in GET /api/distributions/history.
type historyPoint struct {
	// ScanID is the scan.
	ScanID string `json:"scan_id"`
	// Timestamp is when the scan ran.
	Timestamp time.Time `json:"timestamp"`
	// Distribution is the field's distribution in that scan, nil when the scan has none.
	Distribution *report.Distribution `json:"distribution"`
}

// historyResponse is the body of GET /api/distributions/history.
type historyResponse struct {
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// Scope is the norm scope.
	Scope string `json:"scope"`
	// Points lists the field's distribution per scan, oldest first.
	Points []historyPoint `json:"points"`
}

// handleGetDistributionHistory returns one field's distribution across the most recent scans,
// oldest first, so a chart can draw the norm and its band over time. scanner and field are
// required; scans defaults to 24 and is capped at 50.
func (s *Server) handleGetDistributionHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scannerName, field := q.Get("scanner"), q.Get("field")
	if scannerName == "" || field == "" {
		writeError(w, http.StatusBadRequest, "scanner and field are required")
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = report.NormScopeFleet
	}
	series, ok := s.loadScanSeries(w, r, queryLimit(r, "scans", 24, maxHistoryScans), "distribution history")
	if !ok {
		return
	}
	out := historyResponse{Scanner: scannerName, Field: field, Scope: scope, Points: make([]historyPoint, 0, len(series))}
	for _, in := range series {
		p := historyPoint{ScanID: in.ID, Timestamp: in.Timestamp}
		for _, d := range in.build().Distributions {
			if d.Scope == scope && d.Scanner == scannerName && d.Field == field {
				d := d
				p.Distribution = &d
				break
			}
		}
		out.Points = append(out.Points, p)
	}
	writeJSON(w, http.StatusOK, out)
}

// attributionResponse is the body of GET /api/score/attribution.
type attributionResponse struct {
	// ScanID is the scan the score came from.
	ScanID string `json:"scan_id"`
	// Score is the fleet score.
	Score report.FleetScore `json:"score"`
	// Attribution is the cost ledger behind the score.
	Attribution *report.ScoreAttribution `json:"attribution"`
}

// handleGetScoreAttribution returns the fleet score of one scan with the full ledger of what it
// cost: every term, every finding rule and cluster charged, and the caps applied.
func (s *Server) handleGetScoreAttribution(w http.ResponseWriter, r *http.Request) {
	in, ok := s.loadScanInput(w, r, "score attribution")
	if !ok {
		return
	}
	rpt := in.build()
	writeJSON(w, http.StatusOK, attributionResponse{ScanID: in.ID, Score: rpt.FleetScore, Attribution: rpt.ScoreAttribution})
}

// handleGetDrift returns the drift ledger over a window of scans: the most recent ?scans=N
// (default 10, at most 50), or the scans between ?since= and ?until= (RFC 3339), keeping the
// newest ?scans=N (default and ceiling 50).
func (s *Server) handleGetDrift(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var series []*scanInput
	if q.Get("since") != "" || q.Get("until") != "" {
		var ok bool
		if series, ok = s.loadScanRange(w, r); !ok {
			return
		}
	} else {
		var ok bool
		if series, ok = s.loadScanSeries(w, r, queryLimit(r, "scans", 10, maxHistoryScans), "drift"); !ok {
			return
		}
	}
	scans := make([]report.ScanReport, 0, len(series))
	for _, in := range series {
		scans = append(scans, report.ScanReport{ID: in.ID, Report: in.build()})
	}
	writeJSON(w, http.StatusOK, report.DriftLedger(scans))
}

// loadScanRange returns the stored scans between ?since= and ?until=, oldest first, keeping
// the newest ?scans=N (default and ceiling maxHistoryScans). A missing bound is open. It writes
// the error response and returns ok=false on a bad bound or a store failure.
func (s *Server) loadScanRange(w http.ResponseWriter, r *http.Request) ([]*scanInput, bool) {
	since, ok := queryTime(w, r, "since", time.Unix(0, 0).UTC())
	if !ok {
		return nil, false
	}
	until, ok := queryTime(w, r, "until", time.Now().UTC())
	if !ok {
		return nil, false
	}
	scans, err := s.store.GetScansByTimeRange(r.Context(), since, until)
	if err != nil {
		s.log.Error("drift: scans by time range", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return nil, false
	}
	keep := queryLimit(r, "scans", maxHistoryScans, maxHistoryScans)
	if len(scans) > keep {
		scans = scans[:keep]
	}
	opts := s.reportOptions(r.Context(), s.log)
	out := make([]*scanInput, 0, len(scans))
	for i := len(scans) - 1; i >= 0; i-- {
		in, ok := s.scanInputWith(w, r, scans[i], opts, "drift")
		if !ok {
			return nil, false
		}
		out = append(out, in)
	}
	return out, true
}

// queryTime parses the RFC 3339 query parameter key, returning def when it is absent. A malformed
// value writes a 400 and returns ok=false.
func queryTime(w http.ResponseWriter, r *http.Request, key string, def time.Time) (time.Time, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		writeError(w, http.StatusBadRequest, key+" must be RFC 3339")
		return time.Time{}, false
	}
	return t, true
}
