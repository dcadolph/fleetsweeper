package report

import (
	"fmt"
	"strings"
	"testing"
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
