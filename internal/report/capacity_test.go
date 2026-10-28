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
		Status: "critical", Sig: clusterSignals{nodeCount: 4, memPct: 90, memPressure: 2, oomEvents: true}, WantText: "Add 2 node(s)",
	}, { // Test 1: OOM kills under pressure with memory below target.
		Status: "critical", Sig: clusterSignals{nodeCount: 4, memPct: 40, memPressure: 1, oomEvents: true}, WantText: "load is uneven",
	}, { // Test 2: Memory pressure with memory below target.
		Status: "critical", Sig: clusterSignals{nodeCount: 4, memPct: 40, memPressure: 1}, WantText: "while average memory is 40%",
	}, { // Test 3: Exhaustion with memory below target.
		Status: "critical", Sig: clusterSignals{nodeCount: 4, memPct: 40}, WantText: "Check node conditions",
	}, { // Test 4: Exhaustion with memory above target.
		Status: "critical", Sig: clusterSignals{nodeCount: 4, memPct: 95}, WantText: "Add 2 node(s)",
	}, { // Test 5: Scheduling failures with memory below target.
		Status: "strained", Sig: clusterSignals{nodeCount: 1, memPct: 0, schedFail: true}, WantText: "Check pod requests",
	}, { // Test 6: Scheduling failures with memory above target.
		Status: "strained", Sig: clusterSignals{nodeCount: 3, memPct: 80, schedFail: true}, WantText: "Add 1 node(s)",
	}, { // Test 7: Elevated CPU with memory below target.
		Status: "strained", Sig: clusterSignals{nodeCount: 3, cpuPct: 92, memPct: 50}, WantText: "Monitor closely.",
	}, { // Test 8: No nodes reported.
		Status: "strained", Sig: clusterSignals{schedFail: true}, WantText: "Check pod requests",
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
			if strings.Contains(got, "memory is 0%") {
				t.Errorf("recommendation %q reports a missing memory reading as zero", got)
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
		return clusterSignals{hasMetrics: true, cpuPct: cpu, memPct: mem}
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

// TestAnalyzeCapacity verifies status assignment and event signal detection
// from report sections.
func TestAnalyzeCapacity(t *testing.T) {
	t.Parallel()
	oom := map[string]any{"top_warning_reasons": []any{map[string]any{"reason": "OOMKilling"}}}
	sched := map[string]any{
		"top_warning_reasons": []any{map[string]any{"reason": "FailedScheduling"}},
	}
	tests := []struct {
		Sections        map[string]map[string]any
		WantStatus      string
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
			"metrics": {"c1": map[string]any{"avg_memory_percent": 75.0}},
		},
		WantStatus: capacityBusy,
	}, { // Test 3: A quiet cluster is healthy.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_memory_percent": 30.0}},
		},
		WantStatus: capacityHealthy,
	}, { // Test 4: Events for another cluster leave this one healthy.
		Sections: map[string]map[string]any{
			"metrics": {"c1": map[string]any{"avg_memory_percent": 30.0}},
			"events":  {"c2": oom},
		},
		WantStatus: capacityHealthy,
	}, { // Test 5: Event data that is not an object is ignored.
		Sections:   map[string]map[string]any{"events": {"c1": "bad"}},
		WantStatus: capacityHealthy,
	}, { // Test 6: Event data without warning reasons is ignored.
		Sections:   map[string]map[string]any{"events": {"c1": map[string]any{}}},
		WantStatus: capacityHealthy,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := AnalyzeCapacity(testReport(test.Sections), nil)
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
		})
	}
}
