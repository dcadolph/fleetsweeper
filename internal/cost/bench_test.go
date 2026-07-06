package cost

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// BenchmarkParseCSV measures CSV parsing for a typical 200-row fleet.
func BenchmarkParseCSV(b *testing.B) {
	csv := buildCSV(200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCSV(strings.NewReader(csv))
	}
}

// BenchmarkCorrelate measures the join of a parsed CSV with per-cluster
// scores, which is what runs on every dashboard cost-panel render.
func BenchmarkCorrelate(b *testing.B) {
	csv := buildCSV(200)
	m, _ := ParseCSV(strings.NewReader(csv))

	r := &report.Report{
		Clusters: make([]string, 200),
	}
	for i := range r.Clusters {
		name := fmt.Sprintf("cluster-%03d", i)
		r.Clusters[i] = name
		r.ClusterHealths = append(r.ClusterHealths, report.ClusterHealth{
			Name: name, Status: "healthy", NodeCount: 5, HealthyNodes: 5,
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Correlate(r, m)
	}
}

// buildCSV returns a synthetic n-row cost CSV with a header and uniform
// per-cluster cost.
func buildCSV(n int) string {
	var b strings.Builder
	b.WriteString("cluster,period,cost_usd\n")
	for i := range n {
		fmt.Fprintf(&b, "cluster-%03d,2026-05,%d.00\n", i, 100+i)
	}
	return b.String()
}
