package report

import (
	"fmt"
	"math"
)

// minMajoritySample is the smallest population the leave-one-out majority
// diff runs on. Two clusters that disagree give no basis for calling either
// one the outlier.
const minMajoritySample = 3

// detectMajorityOutliers runs the leave-one-out majority diff over every
// non-uniform section of r. It is the outlier detector for populations of
// minMajoritySample to minMADSample-1 clusters, where MAD over the whole
// population is unstable. Every result is marked LimitedSample, its severity
// is capped at warning, and its Scope is scope.
func detectMajorityOutliers(r *Report, threshold float64, scope string) []OutlierResult {
	var outliers []OutlierResult
	for scannerName, sec := range r.Sections {
		if sec.Uniform {
			continue
		}
		flat := flattenSection(r.Clusters, sec)
		for _, field := range collectFields(flat) {
			if _, skip := skipFields[field]; skip {
				continue
			}
			var o *OutlierResult
			switch {
			case isNumericInFlat(r.Clusters, flat, field):
				o = majorityNumericOutlier(r.Clusters, flat, field, threshold)
			case isArrayInFlat(r.Clusters, flat, field):
				continue
			default:
				o = majorityStringOutlier(r.Clusters, flat, field)
			}
			if o == nil {
				continue
			}
			o.Field = field
			o.Scanner = scannerName
			o.Scope = scope
			o.LimitedSample = true
			o.Severity = classifySeverity(scannerName, field)
			if o.Severity == SeverityCritical {
				o.Severity = SeverityWarning
			}
			outliers = append(outliers, *o)
		}
	}
	sortOutliers(outliers)
	return outliers
}

// majorityNumericOutlier returns the one cluster that stands apart from peers
// that agree. For each cluster it takes the other clusters' median m and MAD
// d. The others agree when every one is within d of m, and the cluster stands
// apart when its modified z against them exceeds threshold; with d zero any
// difference counts. The result is nil unless exactly one cluster qualifies.
func majorityNumericOutlier(clusters []string, flat map[string]map[string]any, field string, threshold float64) *OutlierResult {
	var names []string
	var vals []float64
	for _, c := range clusters {
		v, ok := toOptionalFloat64(flat[c][field])
		if !ok {
			continue
		}
		names = append(names, c)
		vals = append(vals, v)
	}
	if len(vals) < minMajoritySample || len(vals) >= minMADSample {
		return nil
	}

	var found *OutlierResult
	for i, v := range vals {
		others := make([]float64, 0, len(vals)-1)
		others = append(others, vals[:i]...)
		others = append(others, vals[i+1:]...)
		m := computeMedian(others)
		d := computeMAD(others, m)
		if !withinBand(others, m, d) {
			continue
		}
		var z float64
		switch {
		case v == m:
			continue
		case d == 0:
			z = math.Copysign(maxReportedDeviation, v-m)
		default:
			z = madScale * (v - m) / d
			if math.Abs(z) <= threshold {
				continue
			}
		}
		if found != nil {
			return nil
		}
		found = &OutlierResult{
			Cluster:    names[i],
			Value:      formatNum(v),
			FleetNorm:  formatNum(m),
			Deviation:  math.Abs(z),
			Kind:       NormKindNumeric,
			Median:     m,
			MAD:        d,
			SampleSize: len(vals),
			Threshold:  threshold,
			Z:          z,
		}
	}
	return found
}

// withinBand reports whether every value is within d of m.
func withinBand(vals []float64, m, d float64) bool {
	for _, v := range vals {
		if math.Abs(v-m) > d {
			return false
		}
	}
	return true
}

// majorityStringOutlier returns the one cluster whose value differs when every
// other cluster holds the same value. Clusters without the field are left out
// of the population.
func majorityStringOutlier(clusters []string, flat map[string]map[string]any, field string) *OutlierResult {
	var names, vals []string
	counts := make(map[string]int)
	for _, c := range clusters {
		raw, ok := flat[c][field]
		if !ok || raw == nil {
			continue
		}
		v := fmt.Sprintf("%v", raw)
		names = append(names, c)
		vals = append(vals, v)
		counts[v]++
	}
	n := len(vals)
	if n < minMajoritySample || n >= minMADSample || len(counts) != 2 {
		return nil
	}
	mode := dominantString(counts)
	if counts[mode] != n-1 {
		return nil
	}
	for i, v := range vals {
		if v == mode {
			continue
		}
		share := float64(n-1) / float64(n)
		return &OutlierResult{
			Cluster:    names[i],
			Value:      v,
			FleetNorm:  mode,
			Kind:       NormKindString,
			Mode:       mode,
			ModeShare:  share,
			SampleSize: n,
			Threshold:  share,
		}
	}
	return nil
}
