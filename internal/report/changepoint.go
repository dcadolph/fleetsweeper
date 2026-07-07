package report

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// minSelfDriftBaseline is the minimum number of historical points required
// before the recent segment, so a cluster's own baseline is stable enough to
// judge a shift against.
const minSelfDriftBaseline = 5

// minSelfDriftSample is the minimum length of a metric's time series before
// self-drift is evaluated: a baseline plus at least one recent point.
const minSelfDriftSample = minSelfDriftBaseline + 1

// selfDriftThreshold is the modified z-score a recent value must exceed,
// measured against the cluster's own historical median and MAD, to count as a
// divergence from its past. It matches the cross-cluster outlier default.
const selfDriftThreshold = 3.5

// minSelfDriftRelStep is the fractional change required when the historical
// baseline is perfectly flat (a MAD of zero), so a genuine step is caught
// without flagging trivial wiggle on constant data.
const minSelfDriftRelStep = 0.5

// SelfDrift describes a cluster whose own metric shifted away from its history.
// The cross-cluster view cannot see this because the cluster may still look
// normal next to its peers while having moved sharply from its own past.
type SelfDrift struct {
	// Cluster is the cluster that drifted from its own past.
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produces the metric.
	Scanner string `json:"scanner"`
	// Field is the metric field name.
	Field string `json:"field"`
	// Baseline is the median of the cluster's history before the change point.
	Baseline float64 `json:"baseline"`
	// Latest is the mean of the cluster's values after the change point.
	Latest float64 `json:"latest"`
	// Deviation is the modified z-score of Latest against the baseline, or the
	// fractional step when the baseline was flat.
	Deviation float64 `json:"deviation"`
	// ChangedAt is when the shift began, taken from the change-point scan.
	ChangedAt time.Time `json:"changed_at"`
	// Direction is worsening or improving, calibrated per metric.
	Direction TrendDirection `json:"direction"`
	// Severity is warning for a worsening shift, info for an improving one.
	Severity string `json:"severity"`
}

// DetectSelfDrift finds metrics where one cluster diverged from its own history.
// It mirrors ComputeClusterTrends' inputs: resultsByScan is keyed by scan ID,
// then scanner name, then field. For each tracked metric it locates the single
// most likely change point in the cluster's time series and flags a shift whose
// recent segment is far from the cluster's own pre-change median and MAD.
func DetectSelfDrift(cluster string, scans []ScanMeta, resultsByScan map[string]map[string]map[string]any) []SelfDrift {
	var drifts []SelfDrift

	for _, tf := range trendFields {
		points := seriesFor(tf.Scanner, tf.Field, scans, resultsByScan)
		if len(points) < minSelfDriftSample {
			continue
		}

		vals := make([]float64, len(points))
		for i, p := range points {
			vals[i] = p.Value
		}

		k := changePointIndex(vals)
		if k < minSelfDriftBaseline || k >= len(vals) {
			continue
		}

		med := computeMedian(vals[:k])
		mad := computeMAD(vals[:k], med)
		recentMean := meanFloat(vals[k:])

		var deviation float64
		if mad > 0 {
			z := 0.6745 * (recentMean - med) / mad
			if math.Abs(z) < selfDriftThreshold {
				continue
			}
			deviation = math.Abs(z)
		} else {
			denom := math.Max(math.Abs(med), 1)
			rel := math.Abs(recentMean-med) / denom
			if rel < minSelfDriftRelStep {
				continue
			}
			deviation = rel
		}

		direction := TrendImproving
		if (recentMean > med) == tf.UpIsBad {
			direction = TrendWorsening
		}
		severity := SeverityInfo
		if direction == TrendWorsening {
			severity = SeverityWarning
		}

		drifts = append(drifts, SelfDrift{
			Cluster:   cluster,
			Scanner:   tf.Scanner,
			Field:     tf.Field,
			Baseline:  med,
			Latest:    recentMean,
			Deviation: deviation,
			ChangedAt: points[k].Timestamp,
			Direction: direction,
			Severity:  severity,
		})
	}

	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].Scanner != drifts[j].Scanner {
			return drifts[i].Scanner < drifts[j].Scanner
		}
		return drifts[i].Field < drifts[j].Field
	})
	return drifts
}

// seriesFor builds a cluster's sorted time series for one scanner field.
func seriesFor(scanner, field string, scans []ScanMeta, resultsByScan map[string]map[string]map[string]any) []TrendPoint {
	var points []TrendPoint
	for _, scan := range scans {
		scanResults, ok := resultsByScan[scan.ID]
		if !ok {
			continue
		}
		scannerData, ok := scanResults[scanner]
		if !ok {
			continue
		}
		v, ok := toOptionalFloat64(scannerData[field])
		if !ok {
			continue
		}
		points = append(points, TrendPoint{Timestamp: scan.Timestamp, ScanID: scan.ID, Value: v})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Timestamp.Before(points[j].Timestamp) })
	return points
}

// changePointIndex returns the split index k that maximizes the weighted
// difference in segment means, the standard single change-point statistic.
// Splits leaving fewer than minSelfDriftBaseline points before the change are
// not considered, so the pre-change baseline stays trustworthy. Returns the
// series length when no interior split qualifies.
func changePointIndex(vals []float64) int {
	n := len(vals)
	if n < minSelfDriftSample {
		return n
	}
	best := n
	bestScore := -1.0
	for k := minSelfDriftBaseline; k < n; k++ {
		mb := meanFloat(vals[:k])
		mr := meanFloat(vals[k:])
		weight := math.Sqrt(float64(k*(n-k)) / float64(n))
		score := weight * math.Abs(mr-mb)
		if score > bestScore {
			bestScore = score
			best = k
		}
	}
	return best
}

// meanFloat returns the arithmetic mean of vals, or zero for an empty slice.
func meanFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// SelfDriftFindings turns self-drift detections into findings so a cluster that
// broke from its own history reaches the same surfaces as every other finding.
func SelfDriftFindings(drifts []SelfDrift) []Finding {
	findings := make([]Finding, 0, len(drifts))
	for _, d := range drifts {
		label := ScannerLabels[d.Scanner]
		if label == "" {
			label = d.Scanner
		}
		verb := "rose"
		if d.Latest < d.Baseline {
			verb = "fell"
		}
		findings = append(findings, Finding{
			Title: fmt.Sprintf("%s: %s %s broke from its own baseline", d.Cluster, label, d.Field),
			Description: fmt.Sprintf(
				"%s on %s %s from a baseline of %.1f to %.1f, diverging from its own history around %s.",
				d.Field, d.Cluster, verb, d.Baseline, d.Latest, d.ChangedAt.Format("2006-01-02"),
			),
			Severity: d.Severity,
			Cluster:  d.Cluster,
			Scanner:  d.Scanner,
			Affected: []string{d.Field},
		})
	}
	return findings
}
