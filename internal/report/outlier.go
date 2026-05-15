package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

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
}

// DetectOutliers analyzes a report and returns clusters that deviate from fleet
// norms. The threshold controls sensitivity for numeric fields: lower values
// flag more outliers.
func DetectOutliers(r *Report, threshold float64) []OutlierResult {
	var outliers []OutlierResult

	for scannerName, sec := range r.Sections {
		if sec.Uniform || len(sec.PerCluster) < 3 {
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

	// Sort by severity then scanner then cluster.
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
// modified z-scores from the fleet median. Uses MAD (median absolute deviation)
// which is robust to the outliers themselves.
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

	if len(vals) < 3 {
		return nil
	}

	median := computeMedian(vals)
	mad := computeMAD(vals, median)

	if mad == 0 {
		// All values are the same except outliers. Use simple deviation from median.
		var outliers []OutlierResult
		for c, v := range clusterVals {
			if v != median {
				outliers = append(outliers, OutlierResult{
					Cluster:   c,
					Field:     field,
					Value:     formatNum(v),
					FleetNorm: formatNum(median),
					Deviation: math.Abs(v - median),
					Scanner:   scannerName,
					Severity:  classifySeverity(scannerName, field),
				})
			}
		}
		return outliers
	}

	var outliers []OutlierResult
	for c, v := range clusterVals {
		zScore := 0.6745 * (v - median) / mad
		if math.Abs(zScore) > threshold {
			outliers = append(outliers, OutlierResult{
				Cluster:   c,
				Field:     field,
				Value:     formatNum(v),
				FleetNorm: formatNum(median),
				Deviation: math.Abs(zScore),
				Scanner:   scannerName,
				Severity:  classifySeverity(scannerName, field),
			})
		}
	}
	return outliers
}

// detectStringOutliers flags clusters whose string value differs from the mode.
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

	if len(counts) <= 1 {
		return nil
	}

	// Find mode.
	var mode string
	modeCount := 0
	for v, n := range counts {
		if n > modeCount {
			mode = v
			modeCount = n
		}
	}

	// Only flag minority values (not the majority).
	var outliers []OutlierResult
	for c, v := range clusterVals {
		if v != mode {
			outliers = append(outliers, OutlierResult{
				Cluster:   c,
				Field:     field,
				Value:     v,
				FleetNorm: mode,
				Scanner:   scannerName,
				Severity:  classifySeverity(scannerName, field),
			})
		}
	}
	return outliers
}

// detectSetOutliers flags clusters missing items present in the consensus set
// (items in >50% of clusters).
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

	// Consensus: items in >50% of clusters.
	threshold := len(clusterSets) / 2
	consensus := make(map[string]struct{})
	for item, count := range itemCounts {
		if count > threshold {
			consensus[item] = struct{}{}
		}
	}

	var outliers []OutlierResult
	for c, set := range clusterSets {
		var missing []string
		for item := range consensus {
			if _, ok := set[item]; !ok {
				missing = append(missing, item)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			outliers = append(outliers, OutlierResult{
				Cluster:   c,
				Field:     field,
				Value:     fmt.Sprintf("missing %d: %v", len(missing), missing),
				FleetNorm: fmt.Sprintf("%d consensus items", len(consensus)),
				Scanner:   scannerName,
				Severity:  classifySeverity(scannerName, field),
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

// isNumericInFlat checks if a field is numeric in the flattened data.
func isNumericInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		switch m[field].(type) {
		case float64:
			return true
		}
		return false
	}
	return false
}

// isArrayInFlat checks if a field is an array in the flattened data.
func isArrayInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		if _, ok := m[field].([]any); ok {
			return true
		}
		return false
	}
	return false
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
