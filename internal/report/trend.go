package report

import (
	"encoding/json"
	"math"
	"sort"
	"time"
)

// TrendDirection indicates whether a metric is improving, worsening, or stable.
type TrendDirection string

const (
	// TrendStable indicates no significant change.
	TrendStable TrendDirection = "stable"
	// TrendImproving indicates the metric is getting better.
	TrendImproving TrendDirection = "improving"
	// TrendWorsening indicates the metric is getting worse.
	TrendWorsening TrendDirection = "worsening"
)

// TrendPoint represents a metric value at a point in time.
type TrendPoint struct {
	// Timestamp is when this value was observed.
	Timestamp time.Time `json:"timestamp"`
	// ScanID is the scan that produced this value.
	ScanID string `json:"scan_id"`
	// Value is the metric value.
	Value float64 `json:"value"`
}

// ClusterTrend tracks how a specific metric changes over time for one cluster.
type ClusterTrend struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produces the metric.
	Scanner string `json:"scanner"`
	// Field is the metric field name.
	Field string `json:"field"`
	// Points are the historical data points, oldest first.
	Points []TrendPoint `json:"points"`
	// Direction indicates the overall trend.
	Direction TrendDirection `json:"direction"`
}

// FleetTrend tracks a fleet-wide metric over time.
type FleetTrend struct {
	// Scanner is the scanner name.
	Scanner string `json:"scanner"`
	// Field is the metric field name.
	Field string `json:"field"`
	// Direction indicates the overall trend.
	Direction TrendDirection `json:"direction"`
	// Points are fleet-aggregated values over time (e.g. count of unique versions).
	Points []TrendPoint `json:"points"`
}

// trendFields defines which (scanner, field) pairs we track trends for and
// whether "up" is good or bad.
var trendFields = []struct {
	Scanner  string
	Field    string
	UpIsBad  bool
}{
	{"metrics", "avg_cpu_percent", true},
	{"metrics", "avg_memory_percent", true},
	{"metrics", "max_cpu_percent", true},
	{"metrics", "max_memory_percent", true},
	{"node-health", "unhealthy_nodes", true},
	{"node-health", "memory_pressure_nodes", true},
	{"node-health", "not_ready_nodes", true},
	{"events", "warning_events", true},
	{"security", "unenforced_count", true},
	{"network-policies", "namespaces_without_policies", true},
	{"resources", "unschedulable_nodes", true},
}

// ScanMeta identifies a scan for trend analysis without depending on the store package.
type ScanMeta struct {
	// ID is the scan identifier.
	ID string
	// Timestamp is when the scan ran.
	Timestamp time.Time
}

// ComputeClusterTrends builds trends for a single cluster from historical scan
// results. resultsByScan is keyed by scanID then scanner name then field name.
func ComputeClusterTrends(cluster string, scans []ScanMeta, resultsByScan map[string]map[string]map[string]any) []ClusterTrend {
	var trends []ClusterTrend

	for _, tf := range trendFields {
		var points []TrendPoint
		for _, scan := range scans {
			scanResults, ok := resultsByScan[scan.ID]
			if !ok {
				continue
			}
			scannerData, ok := scanResults[tf.Scanner]
			if !ok {
				continue
			}
			v, ok := toOptionalFloat64(scannerData[tf.Field])
			if !ok {
				continue
			}
			points = append(points, TrendPoint{
				Timestamp: scan.Timestamp,
				ScanID:    scan.ID,
				Value:     v,
			})
		}

		if len(points) < 2 {
			continue
		}

		// Sort oldest first.
		sort.Slice(points, func(i, j int) bool {
			return points[i].Timestamp.Before(points[j].Timestamp)
		})

		dir := computeDirection(points, tf.UpIsBad)
		trends = append(trends, ClusterTrend{
			Cluster:   cluster,
			Scanner:   tf.Scanner,
			Field:     tf.Field,
			Points:    points,
			Direction: dir,
		})
	}

	return trends
}

// ComputeFleetTrends analyzes how fleet-wide uniformity changes over time for
// string fields like version. It counts unique values per scan.
func ComputeFleetTrends(scans []ScanMeta, allResults map[string]map[string]map[string]any) []FleetTrend {
	var trends []FleetTrend

	// Track version divergence over time.
	versionTrend := computeUniquenessOverTime(scans, allResults, "version", "git_version")
	if len(versionTrend.Points) >= 2 {
		trends = append(trends, versionTrend)
	}

	return trends
}

// computeUniquenessOverTime counts unique values for a field across all clusters
// per scan. More unique values = more divergence.
func computeUniquenessOverTime(scans []ScanMeta, allResults map[string]map[string]map[string]any, scannerName, field string) FleetTrend {
	ft := FleetTrend{
		Scanner:   scannerName,
		Field:     field,
		Direction: TrendStable,
	}

	for _, scan := range scans {
		scanResults, ok := allResults[scan.ID]
		if !ok {
			continue
		}

		unique := make(map[string]struct{})
		for _, clusterData := range scanResults {
			scannerVal, ok := clusterData[scannerName]
			if !ok {
				continue
			}
			scannerMap, ok := scannerVal.(map[string]any)
			if !ok {
				continue
			}
			if v, ok := scannerMap[field]; ok {
				b, _ := json.Marshal(v)
				unique[string(b)] = struct{}{}
			}
		}

		if len(unique) > 0 {
			ft.Points = append(ft.Points, TrendPoint{
				Timestamp: scan.Timestamp,
				ScanID:    scan.ID,
				Value:     float64(len(unique)),
			})
		}
	}

	// Sort oldest first.
	sort.Slice(ft.Points, func(i, j int) bool {
		return ft.Points[i].Timestamp.Before(ft.Points[j].Timestamp)
	})

	if len(ft.Points) >= 2 {
		ft.Direction = computeDirection(ft.Points, true)
	}

	return ft
}

// computeDirection determines if a metric is trending up (worsening if upIsBad),
// down (improving if upIsBad), or stable. Uses simple linear regression slope.
func computeDirection(points []TrendPoint, upIsBad bool) TrendDirection {
	if len(points) < 2 {
		return TrendStable
	}

	// Simple linear regression.
	n := float64(len(points))
	var sumX, sumY, sumXY, sumXX float64
	for i, p := range points {
		x := float64(i)
		sumX += x
		sumY += p.Value
		sumXY += x * p.Value
		sumXX += x * x
	}
	denom := n*sumXX - sumX*sumX
	if denom == 0 {
		return TrendStable
	}
	slope := (n*sumXY - sumX*sumY) / denom

	// Normalize slope relative to the mean to determine significance.
	mean := sumY / n
	if mean == 0 {
		mean = 1
	}
	relativeSlope := slope / math.Abs(mean)

	// Threshold: 5% relative change per step is significant.
	if math.Abs(relativeSlope) < 0.05 {
		return TrendStable
	}

	if slope > 0 {
		if upIsBad {
			return TrendWorsening
		}
		return TrendImproving
	}
	if upIsBad {
		return TrendImproving
	}
	return TrendWorsening
}
