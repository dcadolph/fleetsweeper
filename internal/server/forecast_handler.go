package server

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// forecastDefaultLimit is the default number of past scans considered when
// computing a Fleet Score forecast. Tuned to be enough for a meaningful fit
// without rebuilding many reports per request.
const forecastDefaultLimit = 10

// handleGetFleetScoreForecast returns a forecast for the next scan's Fleet
// Score based on linear regression over the last N scans. In demo mode the
// handler returns a synthetic forecast so the dashboard always has a value
// to render without requiring real scan history.
func (s *Server) handleGetFleetScoreForecast(w http.ResponseWriter, r *http.Request) {
	limit := forecastDefaultLimit
	if v := r.URL.Query().Get("scans"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	history := s.fleetScoreHistory(r.Context(), limit)

	forecast := report.ForecastFleetScore(history, time.Time{})
	writeJSON(w, http.StatusOK, map[string]any{
		"history":  history,
		"forecast": forecast,
	})
}

// fleetScoreHistory walks the last `limit` scans and extracts each one's
// Fleet Score. Builds reports on the fly; for fleets large enough that this
// is expensive, operators should rely on the cached value on the dashboard
// and request the forecast less often.
func (s *Server) fleetScoreHistory(ctx context.Context, limit int) []report.FleetScoreHistoryPoint {
	scans, err := s.store.ListScans(ctx, limit)
	if err != nil {
		s.log.Warn("forecast: list scans", zap.Error(err))
		return nil
	}
	out := make([]report.FleetScoreHistoryPoint, 0, len(scans))
	opts := s.reportOptions(ctx, s.log)
	for _, scan := range scans {
		results, err := s.store.GetScanResults(ctx, scan.ID)
		if err != nil {
			s.log.Warn("forecast: get results", zap.String("scan_id", scan.ID), zap.Error(err))
			continue
		}
		opts.Timestamp = scan.Timestamp
		rpt := s.reports.get(scan.ID, scan.Clusters, results, opts)
		if !rpt.FleetScore.Graded {
			continue
		}
		out = append(out, report.FleetScoreHistoryPoint{
			ScanID:    scan.ID,
			Timestamp: scan.Timestamp,
			Score:     rpt.FleetScore.Score,
		})
	}
	return out
}

// clusterForecast is the per-cluster row returned by /api/forecast/clusters.
type clusterForecast struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// CurrentScore is the cluster's score from the most recent scan.
	CurrentScore int `json:"current_score"`
	// Forecast is the projected next score with confidence band.
	Forecast report.FleetScoreForecast `json:"forecast"`
}

// handleGetClusterForecasts returns a per-cluster forecast list ranked so the
// most likely-to-degrade clusters come first. Allows operators to triage by
// projected trajectory rather than only by current state.
func (s *Server) handleGetClusterForecasts(w http.ResponseWriter, r *http.Request) {
	limit := forecastDefaultLimit
	if v := r.URL.Query().Get("scans"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	histories, currentByCluster := s.clusterScoreHistories(r.Context(), limit)

	out := make([]clusterForecast, 0, len(histories))
	for cluster, hist := range histories {
		fc := report.ForecastFleetScore(hist, time.Time{})
		out = append(out, clusterForecast{
			Cluster:      cluster,
			CurrentScore: currentByCluster[cluster],
			Forecast:     fc,
		})
	}

	// Rank: degrading and sufficient first; tie-break by lower predicted score.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		aDelta := a.Forecast.Predicted - a.CurrentScore
		bDelta := b.Forecast.Predicted - b.CurrentScore
		aSig := a.Forecast.Sufficient
		bSig := b.Forecast.Sufficient
		if aSig != bSig {
			return aSig
		}
		if aDelta != bDelta {
			return aDelta < bDelta
		}
		return a.Forecast.Predicted < b.Forecast.Predicted
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"forecasts": out,
	})
}

// clusterScoreHistories returns, for each cluster, its score time series over
// the most recent `limit` scans plus a map of the cluster's most recent score
// for delta computation.
func (s *Server) clusterScoreHistories(ctx context.Context, limit int) (map[string][]report.FleetScoreHistoryPoint, map[string]int) {
	scans, err := s.store.ListScans(ctx, limit)
	if err != nil {
		s.log.Warn("cluster forecast: list scans", zap.Error(err))
		return nil, nil
	}
	histories := map[string][]report.FleetScoreHistoryPoint{}
	current := map[string]int{}
	opts := s.reportOptions(ctx, s.log)
	for _, scan := range scans {
		results, err := s.store.GetScanResults(ctx, scan.ID)
		if err != nil {
			s.log.Warn("cluster forecast: get results",
				zap.String("scan_id", scan.ID), zap.Error(err))
			continue
		}
		opts.Timestamp = scan.Timestamp
		rpt := s.reports.get(scan.ID, scan.Clusters, results, opts)
		for _, cs := range report.ComputeClusterScores(rpt) {
			histories[cs.Cluster] = append(histories[cs.Cluster],
				report.FleetScoreHistoryPoint{
					ScanID: scan.ID, Timestamp: scan.Timestamp, Score: cs.Score,
				})
			if _, set := current[cs.Cluster]; !set {
				// First seen is the most recent scan since ListScans returns
				// newest first.
				current[cs.Cluster] = cs.Score
			}
		}
	}
	return histories, current
}
