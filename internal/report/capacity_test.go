package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestRecommendNodeCount verifies a recommendation names a node count only
// when memory is above the 70% target, and never tells the reader to add
// zero nodes.
func TestRecommendNodeCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantText string
		Status   string
		Sig      clusterSignals
	}{{ // Test 0: OOM kills under pressure with memory above target.
		Status: "critical", Sig: clusterSignals{utilObs: observed, nodeCount: 4, memPct: 90, memPressure: 2, oomEvents: true}, WantText: "Add 2 node(s)",
	}, { // Test 1: OOM kills under pressure with memory below target.
		Status: "critical", Sig: clusterSignals{utilObs: observed, nodeCount: 4, memPct: 40, memPressure: 1, oomEvents: true}, WantText: "load is uneven",
	}, { // Test 2: Memory pressure with memory below target.
		Status: "critical", Sig: clusterSignals{utilObs: observed, nodeCount: 4, memPct: 40, memPressure: 1}, WantText: "while average memory is 40%",
	}, { // Test 3: Exhaustion with memory below target.
		Status: "critical", Sig: clusterSignals{utilObs: observed, nodeCount: 4, memPct: 40}, WantText: "Check node conditions",
	}, { // Test 4: Exhaustion with memory above target.
		Status: "critical", Sig: clusterSignals{utilObs: observed, nodeCount: 4, memPct: 95}, WantText: "Add 2 node(s)",
	}, { // Test 5: Scheduling failures with memory unobserved.
		Status: "strained", Sig: clusterSignals{nodeCount: 1, schedFail: true}, WantText: "Check pod requests",
	}, { // Test 6: Scheduling failures with memory above target.
		Status: "strained", Sig: clusterSignals{utilObs: observed, nodeCount: 3, memPct: 80, schedFail: true}, WantText: "Add 1 node(s)",
	}, { // Test 7: Elevated CPU with memory below target.
		Status: "strained", Sig: clusterSignals{utilObs: observed, nodeCount: 3, cpuPct: 92, memPct: 50}, WantText: "Monitor closely.",
	}, { // Test 8: No nodes reported.
		Status: "strained", Sig: clusterSignals{schedFail: true}, WantText: "Check pod requests",
	}, { // Test 9: Disk pressure with utilization unobserved names the gap, not a zero.
		Status: "strained", Sig: clusterSignals{diskPressure: 1, utilGap: "the gap"},
		WantText: "utilization is unknown: the gap",
	}, { // Test 10: Critical with nodes down and utilization unobserved prints no load.
		Status: "critical", Sig: clusterSignals{nodeCount: 3, notReady: 1, diskPressure: 1, oomEvents: true},
		WantText: "1 node(s) are not Ready. Investigate node conditions before scaling.",
	}, { // Test 11: An unknown status names the missing read.
		Status: capacityUnknown, Sig: clusterSignals{utilGap: "the gap"}, WantText: "Utilization is unknown: the gap",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := recommend(test.Sig, test.Status)
			if !strings.Contains(got, test.WantText) {
				t.Errorf("recommendation %q does not contain %q", got, test.WantText)
			}
			if strings.Contains(got, "Add 0 node") || strings.Contains(got, " 0 additional node") {
				t.Errorf("recommendation %q prescribes zero nodes", got)
			}
			if !test.Sig.utilObs.seen() && strings.Contains(got, "%") {
				t.Errorf("recommendation %q reports a percentage it never observed", got)
			}
		})
	}
}

// TestGroupComparison verifies a cluster is compared to the median of the
// peers the metrics scanner read: a blind peer neither drags the median down
// nor gets compared, and one hot peer does not make the rest look deviant.
func TestGroupComparison(t *testing.T) {
	t.Parallel()
	read := func(cpu, mem float64) clusterSignals {
		return clusterSignals{utilObs: observed, cpuPct: cpu, memPct: mem}
	}
	peers := []string{"a", "b", "c", "d", "e"}
	tests := []struct {
		Signals   map[string]clusterSignals
		Cluster   string
		WantText  string
		WantEmpty bool
	}{{ // Test 0: Two blind peers are left out, so the others are within range.
		Signals: map[string]clusterSignals{"a": read(50, 55), "b": read(52, 56), "c": read(51, 54), "d": {}, "e": {}},
		Cluster: "a", WantText: "Within normal range",
	}, { // Test 1: A blind cluster itself is not compared.
		Signals: map[string]clusterSignals{"a": read(50, 55), "b": read(52, 56), "c": read(51, 54), "d": {}, "e": {}},
		Cluster: "d", WantEmpty: true,
	}, { // Test 2: One hot peer does not move the median enough to flag a quiet cluster.
		Signals: map[string]clusterSignals{"a": read(50, 55), "b": read(52, 56), "c": read(51, 54), "d": read(95, 92), "e": read(53, 55)},
		Cluster: "a", WantText: "Within normal range",
	}, { // Test 3: The hot cluster is flagged against the median of the rest.
		Signals: map[string]clusterSignals{"a": read(50, 55), "b": read(52, 56), "c": read(51, 54), "d": read(95, 92), "e": read(53, 55)},
		Cluster: "d", WantText: "than the group \"g\" median",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := groupComparison(test.Cluster, "g", peers, test.Signals)
			if test.WantEmpty {
				if got != "" {
					t.Errorf("want no comparison, got %q", got)
				}
				return
			}
			if !strings.Contains(got, test.WantText) {
				t.Errorf("comparison %q does not contain %q", got, test.WantText)
			}
		})
	}
}

// TestCapacityHealthyRaisesNoFinding verifies a healthy cluster's capacity
// produces no finding, so being healthy costs no score.
func TestCapacityHealthyRaisesNoFinding(t *testing.T) {
	t.Parallel()
	r := &Report{Capacity: []CapacityAnalysis{{Cluster: "a", Status: "healthy"}, {Cluster: "b", Status: "busy"}}}
	findings := capacityFindings(r)
	rules := make([]string, 0, len(findings))
	for _, f := range findings {
		rules = append(rules, f.Cluster+" "+f.Rule)
	}
	if diff := cmp.Diff([]string{"b metrics/capacity-busy"}, rules); diff != "" {
		t.Errorf("findings mismatch (-want +got):\n%s", diff)
	}
}

// TestAnalyzeCapacity verifies status assignment, event signal detection, and that a cluster
// without observed utilization gets no utilization or headroom figure and an unknown status
// when nothing else marks it strained or critical.
func TestAnalyzeCapacity(t *testing.T) {
	t.Parallel()
	oom := map[string]any{"top_warning_reasons": []any{map[string]any{"reason": "OOMKilling"}}}
	sched := map[string]any{
		"top_warning_reasons": []any{map[string]any{"reason": "FailedScheduling"}},
	}
	nodes := map[string]any{"node_count": 3, "healthy_nodes": 3}
	tests := []struct {
		Sections        map[string]map[string]any
		Degraded        []ScannerStatus
		WantHeadroomCPU *float64
		WantHeadroomMem *float64
		WantStatus      string
		WantText        string
		WantOOM         bool
		WantSchedFailed bool
	}{{ // Test 0: OOMKilling with memory pressure is critical.
		Sections: map[string]map[string]any{
			"events":      {"c1": oom},
			"node-health": {"c1": map[string]any{"memory_pressure_nodes": 1}},
		},
		WantStatus: capacityCritical, WantOOM: true,
	}, { // Test 1: FailedScheduling alone is strained.
		Sections:   map[string]map[string]any{"events": {"c1": sched}},
		WantStatus: capacityStrained, WantSchedFailed: true,
	}, { // Test 2: Memory at 75 percent is busy.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_cpu_percent": 40.0, "avg_memory_percent": 75.0}},
		},
		WantStatus: capacityBusy, WantHeadroomCPU: new(60.0), WantHeadroomMem: new(25.0),
	}, { // Test 3: A quiet cluster is healthy.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_cpu_percent": 20.0, "avg_memory_percent": 30.0}},
		},
		WantStatus: capacityHealthy, WantHeadroomCPU: new(80.0), WantHeadroomMem: new(70.0),
	}, { // Test 4: Events for another cluster leave this one healthy.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_cpu_percent": 20.0, "avg_memory_percent": 30.0}},
			"events":  {"c2": oom},
		},
		WantStatus: capacityHealthy, WantHeadroomCPU: new(80.0), WantHeadroomMem: new(70.0),
	}, { // Test 5: Event data that is not an object is ignored, and no metrics is unknown.
		Sections:   map[string]map[string]any{"events": {"c1": "bad"}},
		WantStatus: capacityUnknown,
	}, { // Test 6: Event data without warning reasons is ignored, and no metrics is unknown.
		Sections:   map[string]map[string]any{"events": {"c1": map[string]any{}}},
		WantStatus: capacityUnknown,
	}, { // Test 7: No metrics section invents no headroom and names the scanner that never ran.
		Sections:   map[string]map[string]any{"node-health": {"c1": nodes}},
		WantStatus: capacityUnknown, WantText: "the metrics scanner did not run",
	}, { // Test 8: A degraded metrics run with no node percentages is unknown.
		Sections: map[string]map[string]any{
			"node-health": {"c1": nodes},
			"metrics":     {"c1": map[string]any{"available": true, "node_count": 3, "nodes_with_usage": 0}},
		},
		Degraded:   []ScannerStatus{{Cluster: "c1", Scanner: "metrics", State: "degraded"}},
		WantStatus: capacityUnknown, WantText: "list nodes",
	}, { // Test 9: An errored metrics run is unknown and names the failed read.
		Sections:   map[string]map[string]any{"node-health": {"c1": nodes}},
		Degraded:   []ScannerStatus{{Cluster: "c1", Scanner: "metrics", State: "errored"}},
		WantStatus: capacityUnknown, WantText: "node metrics read failed",
	}, { // Test 10: A cluster that does not serve the metrics API is unknown.
		Sections: map[string]map[string]any{
			"node-health": {"c1": nodes},
			"metrics":     {"c1": map[string]any{"available": false, "node_count": 0}},
		},
		Degraded:   []ScannerStatus{{Cluster: "c1", Scanner: "metrics", State: "unavailable"}},
		WantStatus: capacityUnknown, WantText: "does not serve the metrics.k8s.io API",
	}, { // Test 11: Disk pressure without metrics is strained with no invented percentage.
		Sections: map[string]map[string]any{
			"node-health": {"c1": map[string]any{"node_count": 3, "disk_pressure_nodes": 1}},
		},
		WantStatus: capacityStrained, WantText: "utilization is unknown",
	}, { // Test 12: Utilization from a degraded run keeps its figure and says so.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_cpu_percent": 20.0, "avg_memory_percent": 30.0}},
		},
		Degraded:   []ScannerStatus{{Cluster: "c1", Scanner: "metrics", State: "degraded"}},
		WantStatus: capacityHealthy, WantHeadroomCPU: new(80.0), WantHeadroomMem: new(70.0),
		WantText: partialScanNote,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := testReport(test.Sections)
			r.Degraded = test.Degraded
			got := analyzeCapacity(r, nil)
			var ca CapacityAnalysis
			for _, a := range got {
				if a.Cluster == "c1" {
					ca = a
				}
			}
			if ca.Cluster != "c1" {
				t.Fatalf("no analysis for c1 in %d results", len(got))
			}
			if diff := cmp.Diff(test.WantStatus, ca.Status); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantOOM, ca.HasOOMEvents); diff != "" {
				t.Errorf("oom mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantSchedFailed, ca.HasSchedulingFailures); diff != "" {
				t.Errorf("scheduling mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantHeadroomCPU, ca.HeadroomCPU); diff != "" {
				t.Errorf("cpu headroom mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantHeadroomMem, ca.HeadroomMemory); diff != "" {
				t.Errorf("memory headroom mismatch (-want +got):\n%s", diff)
			}
			if test.WantHeadroomMem == nil && (ca.CPUUtilization != nil || ca.MemoryUtilization != nil) {
				t.Errorf("utilization reported without an observed reading: cpu %v, memory %v",
					ca.CPUUtilization, ca.MemoryUtilization)
			}
			if !strings.Contains(ca.Recommendation, test.WantText) {
				t.Errorf("recommendation %q does not contain %q", ca.Recommendation, test.WantText)
			}
			if test.WantHeadroomMem == nil && strings.Contains(ca.Recommendation, "%") {
				t.Errorf("recommendation %q reports a percentage it never observed", ca.Recommendation)
			}
			if test.WantStatus == capacityUnknown && ca.NodesNeededForTarget != 0 {
				t.Errorf("unknown status prescribes %d nodes", ca.NodesNeededForTarget)
			}
		})
	}
}
