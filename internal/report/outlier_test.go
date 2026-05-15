package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestDetectOutliers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantOutlierCount    int
		WantOutlierClusters []string
		Name                string
		ClusterCount        int
		OutlierValue        string
		NormalValue         string
	}{{ // Test 0: 50 clusters with same version, 2 outliers.
		Name:                "string outliers",
		ClusterCount:        50,
		NormalValue:         "v1.31.2",
		OutlierValue:        "v1.30.4",
		WantOutlierCount:    2,
		WantOutlierClusters: []string{"cluster-48", "cluster-49"},
	}, { // Test 1: All identical, no outliers.
		Name:             "all uniform",
		ClusterCount:     30,
		NormalValue:      "v1.31.2",
		OutlierValue:     "v1.31.2",
		WantOutlierCount: 0,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			clusters := make([]string, test.ClusterCount)
			results := make(map[string]map[string]scanner.Result, test.ClusterCount)
			for i := 0; i < test.ClusterCount; i++ {
				name := fmt.Sprintf("cluster-%d", i)
				clusters[i] = name
				v := test.NormalValue
				if i >= test.ClusterCount-2 && test.OutlierValue != test.NormalValue {
					v = test.OutlierValue
				}
				results[name] = map[string]scanner.Result{
					"version": {Scanner: "version", Data: map[string]any{"git_version": v}},
				}
			}

			rpt := Build(clusters, results)
			if diff := cmp.Diff(test.WantOutlierCount, len(rpt.Outliers)); diff != "" {
				t.Errorf("outlier count mismatch (-want +got):\n%s", diff)
			}
			if test.WantOutlierClusters != nil {
				gotClusters := make([]string, len(rpt.Outliers))
				for i, o := range rpt.Outliers {
					gotClusters[i] = o.Cluster
				}
				if diff := cmp.Diff(test.WantOutlierClusters, gotClusters); diff != "" {
					t.Errorf("outlier clusters mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestDetectNumericOutliers(t *testing.T) {
	t.Parallel()

	// 50 clusters with node count 5-7, 2 clusters with node count 50.
	clusters := make([]string, 52)
	results := make(map[string]map[string]scanner.Result, 52)
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("cluster-%d", i)
		clusters[i] = name
		nodeCount := float64(5 + i%3)
		results[name] = map[string]scanner.Result{
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": nodeCount, "healthy_nodes": nodeCount, "unhealthy_nodes": float64(0),
				"memory_pressure_nodes": float64(0), "disk_pressure_nodes": float64(0),
				"pid_pressure_nodes": float64(0), "not_ready_nodes": float64(0),
			}},
		}
	}
	// Two outliers with 50 nodes.
	for i := 50; i < 52; i++ {
		name := fmt.Sprintf("cluster-%d", i)
		clusters[i] = name
		results[name] = map[string]scanner.Result{
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": float64(50), "healthy_nodes": float64(50), "unhealthy_nodes": float64(0),
				"memory_pressure_nodes": float64(0), "disk_pressure_nodes": float64(0),
				"pid_pressure_nodes": float64(0), "not_ready_nodes": float64(0),
			}},
		}
	}

	rpt := Build(clusters, results)

	// Should detect the 2 clusters with 50 nodes as outliers on node_count.
	nodeOutliers := 0
	for _, o := range rpt.Outliers {
		if o.Field == "node_count" {
			nodeOutliers++
			if o.Value != "50" {
				t.Errorf("expected outlier value 50, got %s", o.Value)
			}
		}
	}
	if nodeOutliers < 2 {
		t.Errorf("expected at least 2 node_count outliers, got %d", nodeOutliers)
	}
}
