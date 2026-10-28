package report

import (
	"fmt"
	"math"
	"strconv"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// minMajoritySample is the smallest population the leave-one-out majority
// diff runs on. Two clusters that disagree give no basis for calling either
// one the outlier.
const minMajoritySample = 3

// detectMajorityOutliers runs the leave-one-out majority diff over every
// non-uniform section of r. It is the outlier detector for populations of
// minMajoritySample to minMADSample-1 clusters, where MAD over the whole
// population is unstable. Every result is marked LimitedSample, its severity
// is capped at warning, and its Scope is scope. It also returns the
// distribution behind every numeric and string field it evaluated.
func detectMajorityOutliers(r *Report, threshold float64, scope string) ([]OutlierResult, []Distribution) {
	var outliers []OutlierResult
	var dists []Distribution
	for scannerName, sec := range r.Sections {
		if sec.Uniform {
			continue
		}
		flat := flattenSection(r.Clusters, sec)
		prepareFlat(scannerName, flat)
		for _, field := range collectFields(flat) {
			if _, skip := skipFields[field]; skip {
				continue
			}
			var o *OutlierResult
			var dist *Distribution
			switch {
			case isNumericInFlat(r.Clusters, flat, field):
				o = majorityNumericOutlier(r.Clusters, flat, field, threshold)
				dist = majorityNumericDistribution(r.Clusters, flat, field, threshold)
			case isArrayInFlat(r.Clusters, flat, field):
				continue
			default:
				o = majorityStringOutlier(r.Clusters, flat, field)
				dist = majorityStringDistribution(r.Clusters, flat, field)
			}
			if dist != nil {
				dist.Scanner = scannerName
				dist.Field = field
				dist.Scope = scope
				if o != nil {
					markOutliers(dist, []OutlierResult{*o}, true)
				}
				dist.Mass = massOf(*dist)
				dists = append(dists, *dist)
			}
			if o == nil {
				continue
			}
			o.Field = field
			o.Scanner = scannerName
			o.Scope = scope
			o.LimitedSample = true
			o.Severity = classifySeverity(scannerName, field)
			if o.Kind == NormKindNumeric {
				v, _ := strconv.ParseFloat(o.Value, 64)
				o.Severity, o.Favorable = numericSeverity(scannerName, field, v-o.Median)
			}
			if o.Severity == SeverityCritical {
				o.Severity = SeverityWarning
			}
			outliers = append(outliers, *o)
		}
	}
	sortOutliers(outliers)
	sortDistributions(dists)
	return outliers, dists
}

// majorityNumericDistribution returns the distribution of a numeric field over
// a population of minMajoritySample to minMADSample-1 clusters, or nil
// outside that range. Median, MAD, and each Z describe the whole population;
// the caller overwrites the flagged cluster's Z with its leave-one-out score.
func majorityNumericDistribution(clusters []string, flat map[string]map[string]any, field string, threshold float64) *Distribution {
	var vals []float64
	var values []ClusterValue
	for _, c := range clusters {
		v, ok := util.Float64(flat[c][field])
		if !ok {
			continue
		}
		vals = append(vals, v)
		values = append(values, ClusterValue{Cluster: c, Number: &v})
	}
	if len(vals) < minMajoritySample || len(vals) >= minMADSample {
		return nil
	}
	m := util.Median(vals)
	d := computeMAD(vals, m)
	dist := &Distribution{
		Kind: NormKindNumeric, Values: values, Median: m, MAD: d, Threshold: threshold,
		SampleSize: len(vals), LimitedSample: true,
	}
	if d == 0 {
		atMedian := 0
		for _, v := range vals {
			if v == m {
				atMedian++
			}
		}
		dist.Exact = true
		dist.ModeShare = float64(atMedian) / float64(len(vals))
		return dist
	}
	dist.Band = threshold * d / madScale
	for i, v := range vals {
		dist.Values[i].Z = cappedZ(madScale * (v - m) / d)
	}
	return dist
}

// majorityStringDistribution returns the distribution of a string field over a
// population of minMajoritySample to minMADSample-1 clusters, or nil outside
// that range or when every cluster holds the same value. Threshold is the
// share the majority diff requires of the mode: all but one cluster.
func majorityStringDistribution(clusters []string, flat map[string]map[string]any, field string) *Distribution {
	counts := make(map[string]int)
	var values []ClusterValue
	for _, c := range clusters {
		raw, ok := flat[c][field]
		if !ok || raw == nil {
			continue
		}
		v := fmt.Sprintf("%v", raw)
		counts[v]++
		values = append(values, ClusterValue{Cluster: c, Text: v})
	}
	n := len(values)
	if n < minMajoritySample || n >= minMADSample || len(counts) < 2 {
		return nil
	}
	mode := dominantString(counts)
	return &Distribution{
		Kind: NormKindString, Values: values, Threshold: float64(n-1) / float64(n),
		Mode: mode, ModeShare: float64(counts[mode]) / float64(n), SampleSize: n, LimitedSample: true,
	}
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
		v, ok := util.Float64(flat[c][field])
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
		m := util.Median(others)
		d := computeMAD(others, m)
		if !withinBand(others, m, d) {
			continue
		}
		var z float64
		exact := false
		switch {
		case v == m:
			continue
		case d == 0:
			exact = true
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
			Exact:      exact,
		}
		if exact {
			found.ModeShare = float64(len(vals)-1) / float64(len(vals))
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
