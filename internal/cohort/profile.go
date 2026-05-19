package cohort

import (
	"encoding/json"
	"math"
)

// featureSpec defines one dimension of the cluster feature vector. Each spec
// names the scanner and field it pulls from, plus an extractor that converts
// the raw value (which is a JSON-decoded any) into a float. Missing values
// are imputed with the feature's fleet median so clusters with partial scans
// still cluster sensibly.
type featureSpec struct {
	// name is the feature label used for debug output.
	name string
	// scanner is the scanner key in Report.Sections.
	scanner string
	// field is the JSON field within the scanner's per-cluster data.
	field string
	// extract converts the raw JSON value to a float. Returns ok=false when
	// the value is missing or unparseable.
	extract func(any) (float64, bool)
}

// featureSpecs returns the fixed feature schema used to build per-cluster
// vectors. Adding a dimension here is the supported extension point.
func featureSpecs() []featureSpec {
	return []featureSpec{
		{name: "node_count", scanner: "resources", field: "node_count", extract: numericExtractor},
		{name: "namespace_count", scanner: "namespaces", field: "count", extract: numericExtractor},
		{name: "service_count", scanner: "services", field: "count", extract: numericExtractor},
		{name: "ingress_count", scanner: "ingresses", field: "count", extract: numericExtractor},
		{name: "cluster_role_count", scanner: "rbac", field: "cluster_role_count", extract: numericExtractor},
		{name: "crd_count", scanner: "crds", field: "count", extract: numericExtractor},
		{name: "avg_cpu_percent", scanner: "metrics", field: "avg_cpu_percent", extract: numericExtractor},
		{name: "avg_memory_percent", scanner: "metrics", field: "avg_memory_percent", extract: numericExtractor},
		{name: "enforced_count", scanner: "security", field: "enforced_count", extract: numericExtractor},
		{name: "network_policy_count", scanner: "network-policies", field: "count", extract: numericExtractor},
		{name: "quota_count", scanner: "resource-quotas", field: "quota_count", extract: numericExtractor},
		{name: "minor_version", scanner: "version", field: "minor", extract: minorVersionExtractor},
	}
}

// SectionLookup is the minimal interface Profiles needs to walk a Report
// without depending on the report package. Callers wrap their
// Report.Sections in something that satisfies this.
type SectionLookup interface {
	// PerCluster returns the raw per-cluster data for a scanner. The map key
	// is the cluster name. Returns nil when the scanner is absent.
	PerCluster(scanner string) map[string]any
}

// Profiles builds normalized feature vectors for every cluster in the fleet.
// Each feature is min-max normalized across the fleet to [0,1] so dimensions
// with large absolute ranges do not dominate distance calculations. Missing
// values are imputed with the per-feature fleet median before normalization.
// tags maps cluster name to its user-supplied cohort label (empty string when
// none).
func Profiles(clusters []string, sections SectionLookup, tags map[string]string) []ClusterProfile {
	specs := featureSpecs()
	raw := make([][]float64, len(clusters))
	present := make([][]bool, len(clusters))
	for i := range raw {
		raw[i] = make([]float64, len(specs))
		present[i] = make([]bool, len(specs))
	}

	for fi, spec := range specs {
		per := sections.PerCluster(spec.scanner)
		for ci, cluster := range clusters {
			if per == nil {
				continue
			}
			data := per[cluster]
			if data == nil {
				continue
			}
			val, ok := extractField(data, spec.field, spec.extract)
			if !ok {
				continue
			}
			raw[ci][fi] = val
			present[ci][fi] = true
		}
	}

	imputeMissing(raw, present)
	normalize(raw)

	profiles := make([]ClusterProfile, len(clusters))
	for i, name := range clusters {
		profiles[i] = ClusterProfile{
			Name:     name,
			Features: raw[i],
			Tag:      tags[name],
		}
	}
	return profiles
}

// extractField walks a JSON-decoded value to pull out a named field and run
// the spec's extractor on it. Handles both map[string]any (which is what
// json.Unmarshal produces for objects) and pre-decoded structs flattened to
// the same shape upstream.
func extractField(data any, field string, extract func(any) (float64, bool)) (float64, bool) {
	switch v := data.(type) {
	case map[string]any:
		return extract(v[field])
	}
	// Fallback: round-trip through JSON for typed structs.
	b, err := json.Marshal(data)
	if err != nil {
		return 0, false
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, false
	}
	return extract(m[field])
}

// numericExtractor pulls a number out of a JSON-decoded any. Accepts the
// shapes json.Unmarshal produces (float64 for all JSON numbers) plus the int
// variants that show up when callers hand-build maps.
func numericExtractor(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// minorVersionExtractor parses a Kubernetes minor version that may arrive as
// "31", "31+", or as a number. Trailing "+" is stripped because GKE and EKS
// append it to indicate vendor patches.
func minorVersionExtractor(v any) (float64, bool) {
	if n, ok := numericExtractor(v); ok {
		return n, true
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return 0, false
	}
	// Strip trailing "+".
	for len(s) > 0 && s[len(s)-1] == '+' {
		s = s[:len(s)-1]
	}
	var out float64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		out = out*10 + float64(ch-'0')
	}
	return out, true
}

// imputeMissing fills missing feature values with the fleet median for that
// feature. When every value for a feature is missing it stays zero.
func imputeMissing(raw [][]float64, present [][]bool) {
	if len(raw) == 0 {
		return
	}
	cols := len(raw[0])
	for col := 0; col < cols; col++ {
		var observed []float64
		for row := range raw {
			if present[row][col] {
				observed = append(observed, raw[row][col])
			}
		}
		if len(observed) == 0 {
			continue
		}
		med := median(observed)
		for row := range raw {
			if !present[row][col] {
				raw[row][col] = med
			}
		}
	}
}

// normalize rescales each column to [0,1] via min-max. Columns where every
// value is identical collapse to 0 so they contribute nothing to distances
// instead of producing NaN.
func normalize(raw [][]float64) {
	if len(raw) == 0 {
		return
	}
	cols := len(raw[0])
	for col := 0; col < cols; col++ {
		minV := math.Inf(1)
		maxV := math.Inf(-1)
		for row := range raw {
			v := raw[row][col]
			if v < minV {
				minV = v
			}
			if v > maxV {
				maxV = v
			}
		}
		span := maxV - minV
		if span == 0 {
			for row := range raw {
				raw[row][col] = 0
			}
			continue
		}
		for row := range raw {
			raw[row][col] = (raw[row][col] - minV) / span
		}
	}
}

// median returns the median of vals. Caller-owned: vals is sorted in place.
func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	// Insertion sort is fast enough for the per-feature column sizes seen
	// here (fleets larger than a few hundred clusters would warrant sort.Float64s).
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
