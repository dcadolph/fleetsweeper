package report

import (
	"fmt"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// BenchmarkBuild measures the cost of building a Report from a synthetic
// per-cluster results map. Useful for catching accidental quadratic behavior
// in the pipeline (compare → severity → findings → cluster health → outliers).
func BenchmarkBuild(b *testing.B) {
	clusters := makeClusterNames(50)
	results := makeSyntheticResults(clusters)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Build(clusters, results)
	}
}

// BenchmarkBuild_LargeFleet covers the over-20-cluster path that activates
// MAD outlier detection so the regression doesn't get hidden by skipping
// that branch.
func BenchmarkBuild_LargeFleet(b *testing.B) {
	clusters := makeClusterNames(200)
	results := makeSyntheticResults(clusters)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Build(clusters, results)
	}
}

// BenchmarkComputeFleetScore isolates the score math from the surrounding
// report-build cost.
func BenchmarkComputeFleetScore(b *testing.B) {
	r := Build(makeClusterNames(50), makeSyntheticResults(makeClusterNames(50)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeFleetScore(r)
	}
}

// BenchmarkComputeClusterScores walks every cluster in a 50-cluster fleet.
func BenchmarkComputeClusterScores(b *testing.B) {
	r := Build(makeClusterNames(50), makeSyntheticResults(makeClusterNames(50)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeClusterScores(r)
	}
}

// BenchmarkForecastFleetScore measures the OLS fit + interval computation.
func BenchmarkForecastFleetScore(b *testing.B) {
	now := time.Now()
	pts := make([]FleetScoreHistoryPoint, 50)
	for i := range pts {
		pts[i] = FleetScoreHistoryPoint{
			Timestamp: now.Add(time.Duration(i) * time.Hour),
			Score:     80 - i/3,
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ForecastFleetScore(pts, time.Time{})
	}
}

// BenchmarkOLS isolates the raw least-squares fit for a 100-point series.
func BenchmarkOLS(b *testing.B) {
	xs := make([]float64, 100)
	ys := make([]float64, 100)
	for i := range xs {
		xs[i] = float64(i)
		ys[i] = float64(i*2) + 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ols(xs, ys)
	}
}

// makeClusterNames generates n synthetic cluster names with a stable pattern.
func makeClusterNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("cluster-%03d", i)
	}
	return out
}

// makeSyntheticResults returns a results map that exercises divergence
// logic: half the clusters have one value, the other half another.
func makeSyntheticResults(clusters []string) map[string]map[string]scanner.Result {
	out := make(map[string]map[string]scanner.Result, len(clusters))
	for i, c := range clusters {
		val := map[string]any{
			"git_version": "v1.31.2",
			"node_count":  10 + (i % 5),
		}
		if i%2 == 0 {
			val["git_version"] = "v1.30.6"
			val["node_count"] = 15 + (i % 3)
		}
		out[c] = map[string]scanner.Result{
			"version":   {Data: val},
			"resources": {Data: map[string]any{"node_count": val["node_count"]}},
		}
	}
	return out
}
