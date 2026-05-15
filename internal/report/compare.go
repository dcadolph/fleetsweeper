package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// setFields are field names known to contain lists that should be compared as sets.
var setFields = map[string]struct{}{
	"names": {}, "hosts": {}, "policy_types": {}, "versions": {},
}

// skipFields are internal or uninteresting fields that should not generate divergences.
var skipFields = map[string]struct{}{
	"nodes": {}, "services": {}, "ingresses": {}, "policies": {},
	"roles": {}, "bindings": {}, "quotas": {}, "limit_ranges": {},
	"namespaces": {}, "crds": {}, "labels": {}, "conditions": {},
}

// compare builds a SectionReport by checking whether all clusters produced
// identical data for a scanner. When data diverges, it produces Divergence
// entries using type-aware comparison (set, numeric, string).
func compare(clusters []string, perCluster map[string]any) *SectionReport {
	section := &SectionReport{
		Uniform:    true,
		PerCluster: perCluster,
	}

	if len(perCluster) <= 1 {
		return section
	}

	encoded := make(map[string][]byte, len(perCluster))
	for cluster, data := range perCluster {
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		encoded[cluster] = b
	}

	// Quick check: are all JSON representations identical?
	var reference []byte
	for _, b := range encoded {
		if reference == nil {
			reference = b
			continue
		}
		if string(b) != string(reference) {
			section.Uniform = false
			break
		}
	}

	if section.Uniform {
		return section
	}

	section.Divergences = findDivergences(clusters, encoded)
	return section
}

// findDivergences compares top-level JSON fields across clusters using
// type-aware comparison.
func findDivergences(clusters []string, encoded map[string][]byte) []Divergence {
	flat := make(map[string]map[string]any, len(encoded))
	for cluster, b := range encoded {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		flat[cluster] = m
	}

	allFields := make(map[string]struct{})
	for _, m := range flat {
		for k := range m {
			allFields[k] = struct{}{}
		}
	}

	fields := make([]string, 0, len(allFields))
	for f := range allFields {
		if _, skip := skipFields[f]; skip {
			continue
		}
		fields = append(fields, f)
	}
	sort.Strings(fields)

	var divergences []Divergence
	for _, field := range fields {
		if _, isSet := setFields[field]; isSet {
			if d := compareSetField(clusters, flat, field); d != nil {
				divergences = append(divergences, *d)
			}
			continue
		}

		if isNumericField(clusters, flat, field) {
			if d := compareNumericField(clusters, flat, field); d != nil {
				divergences = append(divergences, *d)
			}
			continue
		}

		if d := compareStringField(clusters, flat, field); d != nil {
			divergences = append(divergences, *d)
		}
	}

	return divergences
}

// compareStringField does basic string equality comparison.
func compareStringField(clusters []string, flat map[string]map[string]any, field string) *Divergence {
	values := make(map[string]string, len(clusters))
	var ref string
	uniform := true
	for _, cluster := range clusters {
		m, ok := flat[cluster]
		if !ok {
			values[cluster] = "<missing>"
			uniform = false
			continue
		}
		v := fmt.Sprintf("%v", m[field])
		values[cluster] = v
		if ref == "" {
			ref = v
		} else if v != ref {
			uniform = false
		}
	}
	if uniform {
		return nil
	}
	return &Divergence{Field: field, Values: values}
}

// isNumericField checks if a field contains numeric values across clusters.
func isNumericField(clusters []string, flat map[string]map[string]any, field string) bool {
	for _, cluster := range clusters {
		m, ok := flat[cluster]
		if !ok {
			continue
		}
		switch m[field].(type) {
		case float64, int, int64:
			return true
		}
		return false
	}
	return false
}

// compareNumericField compares numeric values and annotates the divergence with
// min/max/range information.
func compareNumericField(clusters []string, flat map[string]map[string]any, field string) *Divergence {
	values := make(map[string]string, len(clusters))
	nums := make(map[string]float64, len(clusters))
	var min, max float64
	first := true
	uniform := true
	var ref float64

	for _, cluster := range clusters {
		m, ok := flat[cluster]
		if !ok {
			values[cluster] = "<missing>"
			uniform = false
			continue
		}
		n := toFloat64(m[field])
		nums[cluster] = n
		values[cluster] = formatNum(n)
		if first {
			ref = n
			min = n
			max = n
			first = false
		} else {
			if n != ref {
				uniform = false
			}
			if n < min {
				min = n
			}
			if n > max {
				max = n
			}
		}
	}

	if uniform {
		return nil
	}

	// Find the outlier cluster(s) — the one(s) furthest from the mean.
	var sum float64
	for _, n := range nums {
		sum += n
	}
	mean := sum / float64(len(nums))

	var outlier string
	maxDist := 0.0
	for cluster, n := range nums {
		dist := math.Abs(n - mean)
		if dist > maxDist {
			maxDist = dist
			outlier = cluster
		}
	}

	// Annotate each cluster value with context.
	for cluster := range values {
		n := nums[cluster]
		annotation := ""
		if cluster == outlier && len(nums) > 2 {
			annotation = " [outlier]"
		}
		if n == max && max != min {
			annotation += " [highest]"
		}
		if n == min && max != min {
			annotation += " [lowest]"
		}
		values[cluster] = formatNum(n) + strings.TrimSpace(annotation)
		if annotation != "" {
			values[cluster] = formatNum(n) + " " + strings.TrimSpace(annotation)
		}
	}

	return &Divergence{Field: field, Values: values}
}

// compareSetField compares list/array fields as sets and reports items that
// are only present in some clusters.
func compareSetField(clusters []string, flat map[string]map[string]any, field string) *Divergence {
	clusterSets := make(map[string]map[string]struct{}, len(clusters))
	for _, cluster := range clusters {
		m, ok := flat[cluster]
		if !ok {
			continue
		}
		set := make(map[string]struct{})
		if arr, ok := m[field].([]any); ok {
			for _, item := range arr {
				set[fmt.Sprintf("%v", item)] = struct{}{}
			}
		}
		clusterSets[cluster] = set
	}

	// Build union of all items.
	union := make(map[string]struct{})
	for _, set := range clusterSets {
		for item := range set {
			union[item] = struct{}{}
		}
	}

	// Check if all clusters have the same set.
	uniform := true
	for _, set := range clusterSets {
		if len(set) != len(union) {
			uniform = false
			break
		}
	}
	if uniform {
		return nil
	}

	// Build per-cluster value showing which items are present/missing.
	values := make(map[string]string, len(clusters))
	for _, cluster := range clusters {
		set := clusterSets[cluster]
		var present, missing []string
		for item := range union {
			if _, ok := set[item]; ok {
				present = append(present, item)
			} else {
				missing = append(missing, item)
			}
		}
		sort.Strings(present)
		sort.Strings(missing)

		desc := fmt.Sprintf("%d items", len(present))
		if len(missing) > 0 {
			desc += fmt.Sprintf(", missing: %s", strings.Join(missing, ", "))
		}
		values[cluster] = desc
	}

	return &Divergence{Field: field, Values: values}
}

// toFloat64 converts a JSON number to float64.
func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

// formatNum formats a number, dropping the decimal for whole numbers.
func formatNum(n float64) string {
	if n == math.Trunc(n) {
		return fmt.Sprintf("%.0f", n)
	}
	return fmt.Sprintf("%.1f", n)
}
