package report

import (
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestMisCohortFindings verifies a single cluster tagged "prod" but with a
// "dev"-shaped profile is flagged, while correctly-tagged clusters are not.
func TestMisCohortFindings(t *testing.T) {
	t.Parallel()
	clusters := []string{
		"p1", "p2", "p3", "p4",
		"d1", "d2", "d3", "d4",
		"oops", // tagged prod but profile matches dev
	}
	prodResources := map[string]any{"node_count": 12.0}
	devResources := map[string]any{"node_count": 2.0}
	prodMetrics := map[string]any{"avg_cpu_percent": 60.0, "avg_memory_percent": 65.0}
	devMetrics := map[string]any{"avg_cpu_percent": 15.0, "avg_memory_percent": 22.0}
	prodNS := map[string]any{"count": 14.0}
	devNS := map[string]any{"count": 4.0}

	results := map[string]map[string]scanner.Result{}
	for _, c := range []string{"p1", "p2", "p3", "p4"} {
		results[c] = map[string]scanner.Result{
			"resources":  {Scanner: "resources", Data: prodResources},
			"metrics":    {Scanner: "metrics", Data: prodMetrics},
			"namespaces": {Scanner: "namespaces", Data: prodNS},
		}
	}
	for _, c := range []string{"d1", "d2", "d3", "d4"} {
		results[c] = map[string]scanner.Result{
			"resources":  {Scanner: "resources", Data: devResources},
			"metrics":    {Scanner: "metrics", Data: devMetrics},
			"namespaces": {Scanner: "namespaces", Data: devNS},
		}
	}
	results["oops"] = map[string]scanner.Result{
		"resources":  {Scanner: "resources", Data: devResources},
		"metrics":    {Scanner: "metrics", Data: devMetrics},
		"namespaces": {Scanner: "namespaces", Data: devNS},
	}

	tags := map[string]string{
		"p1": "prod", "p2": "prod", "p3": "prod", "p4": "prod",
		"d1": "dev", "d2": "dev", "d3": "dev", "d4": "dev",
		"oops": "prod",
	}

	rpt := Build(clusters, results, BuildOptions{ClusterTags: tags})

	gotMisCohort := 0
	flaggedOops := false
	for _, f := range rpt.Findings {
		if f.Scanner != "cohort" {
			continue
		}
		gotMisCohort++
		if f.Cluster == "oops" {
			flaggedOops = true
		}
	}
	if !flaggedOops {
		t.Errorf("expected mis-cohort finding for cluster oops, got %d total mis-cohort findings", gotMisCohort)
	}
	// No correctly-tagged cluster should be flagged.
	for _, f := range rpt.Findings {
		if f.Scanner != "cohort" {
			continue
		}
		if f.Cluster != "oops" {
			t.Errorf("unexpected mis-cohort finding for %q: %s", f.Cluster, f.Description)
		}
	}
}
