package report

import (
	"fmt"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// largeSyntheticFleet builds n clusters of varied numeric data so a benchmark
// exercises the full engine (sections, outliers, cohorts, findings, score) at
// fleet scale.
func largeSyntheticFleet(n int) ([]string, map[string]map[string]scanner.Result) {
	clusters := make([]string, n)
	results := make(map[string]map[string]scanner.Result, n)
	for i := 0; i < n; i++ {
		c := fmt.Sprintf("cluster-%03d", i)
		clusters[i] = c
		nodes := 3 + (i % 20)
		cpu := float64(30 + (i*7)%60)
		minor := 28 + (i % 4)
		results[c] = map[string]scanner.Result{
			"version":     {Scanner: "version", Data: map[string]any{"git_version": fmt.Sprintf("v1.%d.3", minor), "minor": minor}},
			"resources":   {Scanner: "resources", Data: map[string]any{"node_count": nodes}},
			"node-health": {Scanner: "node-health", Data: map[string]any{"node_count": nodes, "healthy_nodes": nodes, "not_ready_nodes": 0}},
			"metrics":     {Scanner: "metrics", Data: map[string]any{"avg_cpu_percent": cpu, "avg_memory_percent": cpu - 5}},
			"namespaces":  {Scanner: "namespaces", Data: map[string]any{"count": 10 + (i % 30)}},
		}
	}
	return clusters, results
}

// BenchmarkBuildLargeFleet times a full report build over a 200-cluster fleet so
// scale regressions in the engine are visible.
func BenchmarkBuildLargeFleet(b *testing.B) {
	clusters, results := largeSyntheticFleet(200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Build(clusters, results)
	}
}
