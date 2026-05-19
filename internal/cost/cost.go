// Package cost correlates Fleetsweeper findings and per-cluster scores with
// a user-provided cost CSV. The CSV is the "bring your own billing export"
// pattern: Fleetsweeper does not call cloud billing APIs (no SDK deps, no
// credentials), but it can read whatever export the operator already has.
//
// Expected CSV shape:
//
//	cluster,period,cost_usd
//	prod-us-east-1,2026-05,2400.50
//	prod-eu-west-1,2026-05,1980.00
//	store-nyc-42,2026-05,180.25
//
// Headers are case-insensitive. Extra columns are ignored. Periods can be
// any string; the correlator does not interpret them but surfaces the most
// recent period per cluster (lexicographic order, which matches ISO month
// strings like "2026-05" for the common case).
package cost

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// Entry is one row of the cost CSV after normalization.
type Entry struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// Period is a free-form label such as "2026-05" or "2026-W19".
	Period string `json:"period"`
	// USD is the cost figure in US dollars for the period.
	USD float64 `json:"usd"`
}

// Map maps cluster name to its most-recent cost entry. Loaders return this so
// downstream code does not have to filter the raw rows itself.
type Map map[string]Entry

// Analysis is the per-cluster correlation between cost and cluster score
// plus a fleet-wide rollup. Designed to slot into a dashboard panel: total
// drift cost is the hero number, by-cluster list ranks where the dollars go.
type Analysis struct {
	// Currency is the cost currency. Always "USD" today.
	Currency string `json:"currency"`
	// Period is the most-recent period seen across the input rows.
	Period string `json:"period,omitempty"`
	// TotalFleetUSD is the sum of cost entries for clusters in the report.
	TotalFleetUSD float64 `json:"total_fleet_usd"`
	// TotalDriftUSD is the sum of (cluster cost) * (1 - score/100) across
	// clusters with a cost entry. Interpreted as "the share of fleet spend
	// associated with cluster health below perfect".
	TotalDriftUSD float64 `json:"total_drift_usd"`
	// ByCluster ranks per-cluster correlations from worst to best.
	ByCluster []ClusterCost `json:"by_cluster"`
	// MissingCost lists clusters in the report that had no entry in the CSV
	// so operators see what their billing export is missing.
	MissingCost []string `json:"missing_cost,omitempty"`
}

// ClusterCost is one row of the by-cluster analysis.
type ClusterCost struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// Score is the cluster's most recent Fleet/cluster score.
	Score int `json:"score"`
	// CostUSD is the cluster's cost figure for Period.
	CostUSD float64 `json:"cost_usd"`
	// DriftUSD is CostUSD * (1 - Score/100), rounded to the nearest cent.
	DriftUSD float64 `json:"drift_usd"`
	// Period is the period label for the cost figure.
	Period string `json:"period,omitempty"`
}

// LoadCSV reads the cost CSV from path. Returns an empty Map and a nil error
// when path is empty so callers can pass through an unset flag without an
// explicit check.
func LoadCSV(path string) (Map, error) {
	if path == "" {
		return Map{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cost csv: %w", err)
	}
	defer f.Close()
	return ParseCSV(f)
}

// ParseCSV reads CSV from r and returns the most-recent entry per cluster.
// Header row is required; column order is detected by name.
func ParseCSV(r io.Reader) (Map, error) {
	rdr := csv.NewReader(r)
	rdr.TrimLeadingSpace = true
	rows, err := rdr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(rows) == 0 {
		return Map{}, nil
	}

	headerIdx := map[string]int{}
	for i, h := range rows[0] {
		headerIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	requireCols := []string{"cluster", "period", "cost_usd"}
	for _, c := range requireCols {
		if _, ok := headerIdx[c]; !ok {
			return nil, fmt.Errorf("cost csv: missing required column %q", c)
		}
	}

	all := []Entry{}
	for i, row := range rows[1:] {
		cluster := strings.TrimSpace(row[headerIdx["cluster"]])
		period := strings.TrimSpace(row[headerIdx["period"]])
		usdRaw := strings.TrimSpace(row[headerIdx["cost_usd"]])
		if cluster == "" {
			continue
		}
		usd, err := strconv.ParseFloat(usdRaw, 64)
		if err != nil {
			return nil, fmt.Errorf("cost csv row %d: parse cost_usd %q: %w", i+2, usdRaw, err)
		}
		all = append(all, Entry{Cluster: cluster, Period: period, USD: usd})
	}

	out := Map{}
	for _, e := range all {
		existing, ok := out[e.Cluster]
		if !ok || e.Period > existing.Period {
			out[e.Cluster] = e
		}
	}
	return out, nil
}

// Correlate produces an Analysis joining the cost map with the per-cluster
// scores from the report. Clusters missing from the cost map are listed in
// MissingCost. Clusters with cost entries but no score are skipped silently
// (a stale cost CSV is common during cluster rotation).
func Correlate(r *report.Report, costs Map) Analysis {
	if r == nil {
		return Analysis{Currency: "USD"}
	}
	scoresByCluster := map[string]int{}
	for _, cs := range report.ComputeClusterScores(r) {
		scoresByCluster[cs.Cluster] = cs.Score
	}

	out := Analysis{Currency: "USD"}
	var period string
	for _, cluster := range r.Clusters {
		entry, ok := costs[cluster]
		if !ok {
			out.MissingCost = append(out.MissingCost, cluster)
			continue
		}
		if entry.Period > period {
			period = entry.Period
		}
		score, ok := scoresByCluster[cluster]
		if !ok {
			score = 100
		}
		drift := entry.USD * (1 - float64(score)/100)
		out.TotalFleetUSD += entry.USD
		out.TotalDriftUSD += drift
		out.ByCluster = append(out.ByCluster, ClusterCost{
			Cluster:  cluster,
			Score:    score,
			CostUSD:  roundCents(entry.USD),
			DriftUSD: roundCents(drift),
			Period:   entry.Period,
		})
	}
	out.Period = period
	out.TotalFleetUSD = roundCents(out.TotalFleetUSD)
	out.TotalDriftUSD = roundCents(out.TotalDriftUSD)

	sort.SliceStable(out.ByCluster, func(i, j int) bool {
		return out.ByCluster[i].DriftUSD > out.ByCluster[j].DriftUSD
	})
	sort.Strings(out.MissingCost)
	return out
}

// roundCents rounds a USD value to the nearest cent. The JSON wire format
// stays as a float; rounding here keeps downstream charts from rendering
// 23.999999999996 cents and similar floating-point noise.
func roundCents(v float64) float64 {
	if v == 0 {
		return 0
	}
	scaled := v * 100
	if scaled >= 0 {
		return float64(int64(scaled+0.5)) / 100
	}
	return float64(int64(scaled-0.5)) / 100
}
