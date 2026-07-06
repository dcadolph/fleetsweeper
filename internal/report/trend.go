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
	// Confidence describes how trustworthy this direction is: "high", "low",
	// or empty when no direction was computed.
	Confidence string `json:"confidence,omitempty"`
	// RSquared is the coefficient of determination for the fitted slope.
	RSquared float64 `json:"r_squared,omitempty"`
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
	// Confidence describes how trustworthy this direction is.
	Confidence string `json:"confidence,omitempty"`
	// RSquared is the coefficient of determination for the fitted slope.
	RSquared float64 `json:"r_squared,omitempty"`
}

// trendFields defines which (scanner, field) pairs we track trends for and
// whether "up" is good or bad.
var trendFields = []struct {
	Scanner string
	Field   string
	UpIsBad bool
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

		if len(points) < minTrendSample {
			continue
		}

		sort.Slice(points, func(i, j int) bool {
			return points[i].Timestamp.Before(points[j].Timestamp)
		})

		fit := fitDirection(points, tf.UpIsBad)
		trends = append(trends, ClusterTrend{
			Cluster:    cluster,
			Scanner:    tf.Scanner,
			Field:      tf.Field,
			Points:     points,
			Direction:  fit.Direction,
			Confidence: fit.Confidence,
			RSquared:   fit.RSquared,
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

	sort.Slice(ft.Points, func(i, j int) bool {
		return ft.Points[i].Timestamp.Before(ft.Points[j].Timestamp)
	})

	if len(ft.Points) >= minTrendSample {
		fit := fitDirection(ft.Points, true)
		ft.Direction = fit.Direction
		ft.Confidence = fit.Confidence
		ft.RSquared = fit.RSquared
	}

	return ft
}

// minTrendSample is the minimum number of points required before a direction
// is reported. Below this the linear fit is meaningless and the audit found
// the prior threshold of 2 was producing routine "worsening" calls from
// single-deploy noise.
const minTrendSample = 5

// minTrendR2 is the minimum coefficient of determination required for a
// non-stable direction. A low R² means the linear model does not explain the
// variance and the slope sign is unreliable.
const minTrendR2 = 0.25

// minTrendT is the minimum absolute t-statistic on the slope. With t > 2 the
// slope is roughly significant at the 95% level for the kinds of N we see.
const minTrendT = 2.0

// trendFit packages the outputs of a single linear-regression call.
type trendFit struct {
	// Direction is the qualitative result.
	Direction TrendDirection
	// Confidence is "high" when both R² and t-stat clear their thresholds,
	// "low" when the data is too noisy or sparse to commit to a direction.
	Confidence string
	// RSquared is the coefficient of determination of the fit.
	RSquared float64
}

// fitDirection determines if a metric is trending up (worsening if upIsBad),
// down (improving if upIsBad), or stable. The x-axis is elapsed seconds from
// the first point, so irregular scan cadence does not corrupt the slope.
// Significance combines a relative-slope check, R², and a t-statistic so a
// single transient bump does not flip the direction.
func fitDirection(points []TrendPoint, upIsBad bool) trendFit {
	if len(points) < minTrendSample {
		return trendFit{Direction: TrendStable, Confidence: "low"}
	}

	x0 := points[0].Timestamp
	n := float64(len(points))
	var sumX, sumY, sumXY, sumXX float64
	xs := make([]float64, len(points))
	for i, p := range points {
		x := p.Timestamp.Sub(x0).Seconds()
		xs[i] = x
		sumX += x
		sumY += p.Value
		sumXY += x * p.Value
		sumXX += x * x
	}
	denom := n*sumXX - sumX*sumX
	if denom == 0 {
		return trendFit{Direction: TrendStable, Confidence: "low"}
	}
	slope := (n*sumXY - sumX*sumY) / denom
	intercept := (sumY - slope*sumX) / n
	mean := sumY / n

	var ssRes, ssTot float64
	for i, p := range points {
		fitVal := intercept + slope*xs[i]
		ssRes += (p.Value - fitVal) * (p.Value - fitVal)
		ssTot += (p.Value - mean) * (p.Value - mean)
	}
	rSquared := 0.0
	if ssTot > 0 {
		rSquared = 1 - ssRes/ssTot
	}

	scale := math.Abs(mean)
	if scale < 1e-9 {
		scale = math.Max(math.Abs(maxFloat(points)), math.Abs(minFloat(points)))
	}
	if scale < 1e-9 {
		return trendFit{Direction: TrendStable, Confidence: "high", RSquared: rSquared}
	}

	xRange := xs[len(xs)-1] - xs[0]
	if xRange == 0 {
		return trendFit{Direction: TrendStable, Confidence: "low", RSquared: rSquared}
	}
	relativeSlopePerScan := (slope * (xRange / (n - 1))) / scale

	var slopeStdErr float64
	if n > 2 {
		varRes := ssRes / (n - 2)
		slopeStdErr = math.Sqrt(varRes / (sumXX - sumX*sumX/n))
	}
	tStat := 0.0
	if slopeStdErr > 0 {
		tStat = slope / slopeStdErr
	}

	if math.Abs(relativeSlopePerScan) < 0.05 || rSquared < minTrendR2 || math.Abs(tStat) < minTrendT {
		return trendFit{Direction: TrendStable, Confidence: "low", RSquared: rSquared}
	}

	dir := TrendWorsening
	if slope > 0 {
		if !upIsBad {
			dir = TrendImproving
		}
	} else {
		if upIsBad {
			dir = TrendImproving
		}
	}
	return trendFit{Direction: dir, Confidence: "high", RSquared: rSquared}
}

// maxFloat returns the largest Value across points.
func maxFloat(points []TrendPoint) float64 {
	if len(points) == 0 {
		return 0
	}
	v := points[0].Value
	for _, p := range points[1:] {
		if p.Value > v {
			v = p.Value
		}
	}
	return v
}

// minFloat returns the smallest Value across points.
func minFloat(points []TrendPoint) float64 {
	if len(points) == 0 {
		return 0
	}
	v := points[0].Value
	for _, p := range points[1:] {
		if p.Value < v {
			v = p.Value
		}
	}
	return v
}
