package report

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
)

// minMADSample is the minimum number of values required before MAD-based
// outlier detection emits any finding. Below this the median itself is
// unreliable and false positives dominate; the audit flagged the previous
// floor of 3 as statistical garbage.
const minMADSample = 8

// minStringModeMass is the minimum share of the population the mode must hold
// before string outliers are flagged. Without this guard a three-way tied
// version distribution incorrectly flagged 2/3 of the fleet as outliers.
const minStringModeMass = 0.6

// maxReportedDeviation caps the modified z-score a finding reports. A MAD that
// is negligibly small next to the spread can drive the score to infinity for a
// far-off cluster; the cluster is still a real outlier, so it is flagged with a
// capped, finite, JSON-safe deviation rather than an infinity.
const maxReportedDeviation = 1e6

// minSetConsensusShare is the share of the population an item must appear in
// before a set field treats it as part of the consensus.
const minSetConsensusShare = 0.6

// madScale converts a MAD into a standard-deviation-equivalent scale, so the
// modified z-score of a normal population matches its ordinary z-score.
const madScale = 0.6745

// Norm kinds name the detector that measured a fleet-relative field.
const (
	NormKindNumeric = "numeric"
	NormKindString  = "string"
	NormKindSet     = "set"
)

// NormScopeFleet is the scope of a norm computed over the whole fleet. A
// cohort norm carries the cohort name instead.
const NormScopeFleet = "fleet"

// NormBasis states the norm a fleet-relative finding was measured against, so
// a reader can check the claim without rerunning the statistics. Which fields
// apply depends on Kind. Absolute-rule findings carry no NormBasis.
type NormBasis struct {
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the members of a set field present in at least
	// Threshold of the population, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied: the modified z-score for
	// numeric, the minimum mode share for string, and the minimum presence
	// share for set membership.
	Threshold float64 `json:"threshold"`
	// Value is this cluster's value for the field.
	Value string `json:"value"`
	// Z is this cluster's signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
}

// OutlierResult describes a cluster that deviates from the fleet norm.
type OutlierResult struct {
	// Cluster is the cluster that deviates.
	Cluster string `json:"cluster"`
	// Field is the data field that deviates.
	Field string `json:"field"`
	// Value is the cluster's value for the field.
	Value string `json:"value"`
	// FleetNorm is the typical fleet value (median for numeric, mode for string).
	FleetNorm string `json:"fleet_norm"`
	// Deviation is the modified z-score for numeric fields.
	Deviation float64 `json:"deviation,omitempty"`
	// Scanner is the scanner that produced this data.
	Scanner string `json:"scanner"`
	// Severity is critical, warning, or info.
	Severity string `json:"severity"`
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the consensus members of a set field, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied (see NormBasis.Threshold).
	Threshold float64 `json:"threshold"`
	// Z is the signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
}

// Basis returns the norm this outlier was measured against. A finding built
// from an outlier takes its NormBasis from here, so the two never disagree.
func (o OutlierResult) Basis() *NormBasis {
	return &NormBasis{
		Scope:         o.Scope,
		Kind:          o.Kind,
		Median:        o.Median,
		MAD:           o.MAD,
		Mode:          o.Mode,
		ModeShare:     o.ModeShare,
		Consensus:     slices.Clone(o.Consensus),
		Missing:       slices.Clone(o.Missing),
		SampleSize:    o.SampleSize,
		Threshold:     o.Threshold,
		Value:         o.Value,
		Z:             o.Z,
		LimitedSample: o.LimitedSample,
	}
}

// DetectOutliers analyzes a report and returns clusters that deviate from fleet
// norms. The threshold controls sensitivity for numeric fields: lower values
// flag more outliers. The function only emits findings when the sample is
// large enough to be statistically meaningful (see minMADSample).
func DetectOutliers(r *Report, threshold float64) []OutlierResult {
	return detectOutliers(r, threshold, NormScopeFleet)
}

// detectOutliers runs DetectOutliers over r and stamps every result with the
// scope its norm was computed over.
func detectOutliers(r *Report, threshold float64, scope string) []OutlierResult {
	var outliers []OutlierResult

	for scannerName, sec := range r.Sections {
		if sec.Uniform || len(sec.PerCluster) < minMADSample {
			continue
		}

		flat := flattenSection(r.Clusters, sec)
		fields := collectFields(flat)

		for _, field := range fields {
			if _, skip := skipFields[field]; skip {
				continue
			}

			if isNumericInFlat(r.Clusters, flat, field) {
				outliers = append(outliers, detectNumericOutliers(r.Clusters, flat, field, scannerName, threshold)...)
			} else if isArrayInFlat(r.Clusters, flat, field) {
				outliers = append(outliers, detectSetOutliers(r.Clusters, flat, field, scannerName)...)
			} else {
				outliers = append(outliers, detectStringOutliers(r.Clusters, flat, field, scannerName)...)
			}
		}
	}

	for i := range outliers {
		outliers[i].Scope = scope
	}

	sevOrder := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}
	sort.Slice(outliers, func(i, j int) bool {
		if sevOrder[outliers[i].Severity] != sevOrder[outliers[j].Severity] {
			return sevOrder[outliers[i].Severity] < sevOrder[outliers[j].Severity]
		}
		if outliers[i].Scanner != outliers[j].Scanner {
			return outliers[i].Scanner < outliers[j].Scanner
		}
		return outliers[i].Cluster < outliers[j].Cluster
	})

	return outliers
}

// detectNumericOutliers flags clusters where a numeric field is beyond threshold
// modified z-scores from the fleet median. Uses MAD (median absolute deviation),
// which is robust to the outliers themselves. When MAD is zero the population
// is uniform enough that a single non-median value is not statistically
// distinguishable from noise; we emit nothing in that case rather than flagging
// every minority value.
func detectNumericOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string, threshold float64) []OutlierResult {
	vals := make([]float64, 0, len(clusters))
	clusterVals := make(map[string]float64, len(clusters))
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, ok := toOptionalFloat64(m[field])
		if !ok {
			continue
		}
		vals = append(vals, v)
		clusterVals[c] = v
	}

	if len(vals) < minMADSample {
		return nil
	}

	median := computeMedian(vals)
	mad := computeMAD(vals, median)

	if mad == 0 {
		return nil
	}

	var outliers []OutlierResult
	for c, v := range clusterVals {
		zScore := madScale * (v - median) / mad
		absZ := math.Abs(zScore)
		if absZ > threshold {
			// A near-zero MAD can drive the score to infinity for a far value.
			// The cluster is still a real outlier, so cap the reported deviation
			// to keep the finding finite and JSON-safe.
			if math.IsInf(absZ, 0) {
				absZ = maxReportedDeviation
				zScore = math.Copysign(maxReportedDeviation, zScore)
			}
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      formatNum(v),
				FleetNorm:  formatNum(median),
				Deviation:  absZ,
				Scanner:    scannerName,
				Severity:   classifySeverity(scannerName, field),
				Kind:       NormKindNumeric,
				Median:     median,
				MAD:        mad,
				SampleSize: len(vals),
				Threshold:  threshold,
				Z:          zScore,
			})
		}
	}
	return outliers
}

// detectStringOutliers flags clusters whose string value differs from the mode,
// but only when the mode commands at least minStringModeMass of the population.
// Tied or near-tied distributions produce no findings to avoid arbitrary
// majority-vs-minority reports.
func detectStringOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string) []OutlierResult {
	counts := make(map[string]int)
	clusterVals := make(map[string]string, len(clusters))

	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v := fmt.Sprintf("%v", m[field])
		counts[v]++
		clusterVals[c] = v
	}

	if len(counts) <= 1 || len(clusterVals) == 0 {
		return nil
	}

	mode := dominantString(counts)
	if mode == "" {
		return nil
	}
	share := float64(counts[mode]) / float64(len(clusterVals))
	if share < minStringModeMass {
		return nil
	}

	var outliers []OutlierResult
	for c, v := range clusterVals {
		if v != mode {
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      v,
				FleetNorm:  mode,
				Scanner:    scannerName,
				Severity:   classifySeverity(scannerName, field),
				Kind:       NormKindString,
				Mode:       mode,
				ModeShare:  share,
				SampleSize: len(clusterVals),
				Threshold:  minStringModeMass,
			})
		}
	}
	return outliers
}

// dominantString returns the mode of a string population. Ties break
// deterministically by smallest string so callers get stable output.
func dominantString(counts map[string]int) string {
	var mode string
	best := 0
	for v, n := range counts {
		if n > best || (n == best && v < mode) {
			mode = v
			best = n
		}
	}
	return mode
}

// detectSetOutliers flags clusters missing items present in the consensus set.
// Consensus requires an item to appear in at least minSetConsensusShare of
// clusters, eliminating the discontinuity the previous integer-divide
// threshold produced at small N.
func detectSetOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string) []OutlierResult {
	itemCounts := make(map[string]int)
	clusterSets := make(map[string]map[string]struct{}, len(clusters))

	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		set := make(map[string]struct{})
		if arr, ok := m[field].([]any); ok {
			for _, item := range arr {
				s := fmt.Sprintf("%v", item)
				set[s] = struct{}{}
				itemCounts[s]++
			}
		}
		clusterSets[c] = set
	}

	if len(clusterSets) == 0 {
		return nil
	}

	threshold := int(math.Ceil(float64(len(clusterSets)) * minSetConsensusShare))
	var consensus []string
	for item, count := range itemCounts {
		if count >= threshold {
			consensus = append(consensus, item)
		}
	}
	sort.Strings(consensus)

	var outliers []OutlierResult
	for c, set := range clusterSets {
		var missing []string
		for _, item := range consensus {
			if _, ok := set[item]; !ok {
				missing = append(missing, item)
			}
		}
		if len(missing) > 0 {
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      fmt.Sprintf("missing %d: %v", len(missing), missing),
				FleetNorm:  fmt.Sprintf("%d consensus items", len(consensus)),
				Scanner:    scannerName,
				Severity:   classifySeverity(scannerName, field),
				Kind:       NormKindSet,
				Consensus:  slices.Clone(consensus),
				Missing:    missing,
				SampleSize: len(clusterSets),
				Threshold:  minSetConsensusShare,
			})
		}
	}
	return outliers
}

// flattenSection converts per-cluster data to maps of JSON fields.
func flattenSection(clusters []string, sec *SectionReport) map[string]map[string]any {
	flat := make(map[string]map[string]any, len(clusters))
	for _, c := range clusters {
		data, ok := sec.PerCluster[c]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		flat[c] = m
	}
	return flat
}

// collectFields gathers unique field names across all clusters.
func collectFields(flat map[string]map[string]any) []string {
	seen := make(map[string]struct{})
	for _, m := range flat {
		for k := range m {
			seen[k] = struct{}{}
		}
	}
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields
}

// isNumericInFlat reports whether a field is numeric in at least one cluster
// and not non-numeric in any cluster. Earlier this consulted only the first
// cluster, so a leading nil silently classified an otherwise numeric field as
// non-numeric.
func isNumericInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	sawNumeric := false
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, present := m[field]
		if !present || v == nil {
			continue
		}
		if _, ok := v.(float64); ok {
			sawNumeric = true
			continue
		}
		return false
	}
	return sawNumeric
}

// isArrayInFlat reports whether a field is an array in at least one cluster
// and not a non-array in any cluster.
func isArrayInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	sawArray := false
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, present := m[field]
		if !present || v == nil {
			continue
		}
		if _, ok := v.([]any); ok {
			sawArray = true
			continue
		}
		return false
	}
	return sawArray
}

// toOptionalFloat64 attempts to convert a value to float64.
func toOptionalFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// computeMedian returns the median of a sorted copy of vals.
func computeMedian(vals []float64) float64 {
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

// computeMAD returns the median absolute deviation from the median.
func computeMAD(vals []float64, median float64) float64 {
	deviations := make([]float64, len(vals))
	for i, v := range vals {
		deviations[i] = math.Abs(v - median)
	}
	return computeMedian(deviations)
}
