package util

import "sort"

// Float64 converts a numeric value to float64. It accepts the float64 that JSON decoding
// produces and the float32 and int variants hand-built maps carry, and reports false for
// anything else.
func Float64(v any) (float64, bool) {
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

// Median returns the median of vals without reordering it, averaging the middle pair for an
// even count. It returns 0 for empty input.
func Median(vals []float64) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	sorted := make([]float64, n)
	copy(sorted, vals)
	sort.Float64s(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}
