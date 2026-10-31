package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// okRun returns an OK scanner result carrying data.
func okRun(name string, data map[string]any) scanner.Result {
	return scanner.Result{Scanner: name, Data: data}
}

// degradedRun returns a degraded scanner result carrying partial data.
func degradedRun(name string, data map[string]any) scanner.Result {
	return scanner.Result{Scanner: name, State: scanner.StateDegraded, Reason: "list failed", Data: data}
}

// erroredRun returns an errored scanner result with no data.
func erroredRun(name string) scanner.Result {
	return scanner.ErroredResult(name, errors.New("forbidden"))
}

// findingsWithRule returns the findings in fs whose rule is rule.
func findingsWithRule(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// TestObserve reads numeric fields through the accessor on a built and a decoded report.
func TestObserve(t *testing.T) {
	t.Parallel()
	results := map[string]map[string]scanner.Result{
		"c1": {
			"namespaces":      okRun("namespaces", map[string]any{"count": 3, "name": "a"}),
			"resource-quotas": degradedRun("resource-quotas", map[string]any{"namespaces_with_quotas": 0}),
			"certs":           erroredRun("certs"),
			"crds":            {Scanner: "crds", State: scanner.StateUnavailable, Data: map[string]any{"count": 0}},
		},
	}
	built := Build([]string{"c1"}, results)
	blob, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tests := []struct {
		Scanner   string
		Field     string
		WantValue float64
		WantObs   observation
	}{{ // Test 0: An OK run's field is observed.
		Scanner: "namespaces", Field: "count", WantValue: 3, WantObs: observed,
	}, { // Test 1: A degraded run's field is partial.
		Scanner: "resource-quotas", Field: "namespaces_with_quotas", WantValue: 0, WantObs: partial,
	}, { // Test 2: An errored run is unobserved.
		Scanner: "certs", Field: "expiring", WantValue: 0, WantObs: unobserved,
	}, { // Test 3: A scanner that never ran on the cluster is unobserved.
		Scanner: "events", Field: "warning_events", WantValue: 0, WantObs: unobserved,
	}, { // Test 4: A field the run did not emit is unobserved.
		Scanner: "namespaces", Field: "missing", WantValue: 0, WantObs: unobserved,
	}, { // Test 5: A non-numeric field is unobserved.
		Scanner: "namespaces", Field: "name", WantValue: 0, WantObs: unobserved,
	}, { // Test 6: An unavailable run is a trustworthy nothing, so observed.
		Scanner: "crds", Field: "count", WantValue: 0, WantObs: observed,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			for _, r := range []*Report{built, &decoded} {
				gotValue, gotObs := observe(r, test.Scanner, "c1", test.Field)
				if diff := cmp.Diff(test.WantValue, gotValue); diff != "" {
					t.Errorf("value mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(test.WantObs, gotObs); diff != "" {
					t.Errorf("observation mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestObserveString reads string fields through the accessor across run states.
func TestObserveString(t *testing.T) {
	t.Parallel()
	results := map[string]map[string]scanner.Result{
		"c1": {"version": okRun("version", map[string]any{"git_version": "v1.30.0", "major": 1})},
		"c2": {"version": degradedRun("version", map[string]any{"git_version": "v1.29.0"})},
		"c3": {"version": erroredRun("version")},
	}
	r := Build([]string{"c1", "c2", "c3"}, results)
	tests := []struct {
		Cluster   string
		Field     string
		WantValue string
		WantObs   observation
	}{{ // Test 0: An OK string field is observed.
		Cluster: "c1", Field: "git_version", WantValue: "v1.30.0", WantObs: observed,
	}, { // Test 1: A degraded string field is partial.
		Cluster: "c2", Field: "git_version", WantValue: "v1.29.0", WantObs: partial,
	}, { // Test 2: An errored run is unobserved.
		Cluster: "c3", Field: "git_version", WantValue: "", WantObs: unobserved,
	}, { // Test 3: A non-string field is unobserved.
		Cluster: "c1", Field: "major", WantValue: "", WantObs: unobserved,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			gotValue, gotObs := observeString(r, "version", test.Cluster, test.Field)
			if diff := cmp.Diff(test.WantValue, gotValue); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantObs, gotObs); diff != "" {
				t.Errorf("observation mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestWeakest picks the least trustworthy observation and its note.
func TestWeakest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In       []observation
		WantObs  observation
		WantNote string
	}{{ // Test 0: No inputs is observed.
		In: nil, WantObs: observed, WantNote: "",
	}, { // Test 1: One partial input makes the result partial.
		In: []observation{observed, partial}, WantObs: partial, WantNote: partialScanNote,
	}, { // Test 2: One unobserved input makes the result unobserved.
		In: []observation{partial, unobserved, observed}, WantObs: unobserved, WantNote: "",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := weakest(test.In...)
			if diff := cmp.Diff(test.WantObs, got); diff != "" {
				t.Errorf("observation mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNote, got.note()); diff != "" {
				t.Errorf("note mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestQuotaFindingsCoverage keeps the no-quota claim off clusters whose quota run was not complete.
func TestQuotaFindingsCoverage(t *testing.T) {
	t.Parallel()
	ns := okRun("namespaces", map[string]any{"count": 3})
	tests := []struct {
		Runs        map[string]scanner.Result
		WantPartial bool
		WantCount   int
	}{{ // Test 0: An errored quota run with live namespaces claims nothing (R-5).
		Runs:      map[string]scanner.Result{"namespaces": ns, "resource-quotas": erroredRun("resource-quotas")},
		WantCount: 0,
	}, { // Test 1: A degraded quota run reading zero is not proof of no quotas.
		Runs: map[string]scanner.Result{"namespaces": ns, "resource-quotas": degradedRun("resource-quotas",
			map[string]any{"namespaces_with_quotas": 0})},
		WantCount: 0,
	}, { // Test 2: An OK quota run reading zero with live namespaces is the finding.
		Runs: map[string]scanner.Result{"namespaces": ns, "resource-quotas": okRun("resource-quotas",
			map[string]any{"namespaces_with_quotas": 0})},
		WantCount: 1,
	}, { // Test 3: Namespaces from a degraded run still prove namespaces exist.
		Runs: map[string]scanner.Result{
			"namespaces":      degradedRun("namespaces", map[string]any{"count": 3}),
			"resource-quotas": okRun("resource-quotas", map[string]any{"namespaces_with_quotas": 0}),
		},
		WantPartial: true,
		WantCount:   1,
	}, { // Test 4: An errored namespace run leaves the namespace count unknown.
		Runs: map[string]scanner.Result{
			"namespaces":      erroredRun("namespaces"),
			"resource-quotas": okRun("resource-quotas", map[string]any{"namespaces_with_quotas": 0}),
		},
		WantCount: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Build([]string{"c1"}, map[string]map[string]scanner.Result{"c1": test.Runs})
			got := findingsWithRule(quotaFindings(r), "resource-quotas/no-quota")
			if diff := cmp.Diff(test.WantCount, len(got)); diff != "" {
				t.Fatalf("finding count mismatch (-want +got):\n%s", diff)
			}
			if len(got) == 1 {
				gotPartial := strings.HasSuffix(got[0].Description, partialScanNote)
				if diff := cmp.Diff(test.WantPartial, gotPartial); diff != "" {
					t.Errorf("partial note mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestNodeHealthFindingsCoverage reports node pressure from OK and degraded runs only.
func TestNodeHealthFindingsCoverage(t *testing.T) {
	t.Parallel()
	pressure := map[string]any{"node_count": 3, "memory_pressure_nodes": 1, "not_ready_nodes": 1}
	tests := []struct {
		Run         scanner.Result
		WantPartial bool
		WantCount   int
	}{{ // Test 0: An OK run's pressure counts produce findings.
		Run: okRun("node-health", pressure), WantCount: 2,
	}, { // Test 1: A degraded run's positive counts still produce findings, marked partial.
		Run: degradedRun("node-health", pressure), WantPartial: true, WantCount: 2,
	}, { // Test 2: An errored run produces nothing.
		Run: erroredRun("node-health"), WantCount: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Build([]string{"c1"}, map[string]map[string]scanner.Result{"c1": {"node-health": test.Run}})
			got := nodeHealthFindings(r)
			if diff := cmp.Diff(test.WantCount, len(got)); diff != "" {
				t.Fatalf("finding count mismatch (-want +got):\n%s", diff)
			}
			for _, f := range got {
				gotPartial := strings.HasSuffix(f.Description, partialScanNote)
				if diff := cmp.Diff(test.WantPartial, gotPartial); diff != "" {
					t.Errorf("%s partial note mismatch (-want +got):\n%s", f.Rule, diff)
				}
			}
		})
	}
}

// TestEventFindingsCoverage rates warning events per node only when the node count was observed.
func TestEventFindingsCoverage(t *testing.T) {
	t.Parallel()
	nodes := okRun("node-health", map[string]any{"node_count": 100})
	tests := []struct {
		Runs         map[string]scanner.Result
		WantSeverity string
		WantDesc     string
		WantCount    int
	}{{ // Test 0: A known node count rates events per node.
		Runs: map[string]scanner.Result{"node-health": nodes,
			"events": okRun("events", map[string]any{"warning_events": 300})},
		WantSeverity: SeverityWarning,
		WantDesc:     "300 warning events in the last hour across 100 node(s) (3.0 per node).",
		WantCount:    1,
	}, { // Test 1: An unknown node count is not read as one node.
		Runs: map[string]scanner.Result{"node-health": erroredRun("node-health"),
			"events": okRun("events", map[string]any{"warning_events": 150})},
		WantSeverity: SeverityInfo,
		WantDesc:     "150 warning events in the last hour. The node count was not observed, so no per-node rate.",
		WantCount:    1,
	}, { // Test 2: A degraded events run is marked partial.
		Runs: map[string]scanner.Result{"node-health": nodes,
			"events": degradedRun("events", map[string]any{"warning_events": 300})},
		WantSeverity: SeverityWarning,
		WantDesc:     "300 warning events in the last hour across 100 node(s) (3.0 per node)." + partialScanNote,
		WantCount:    1,
	}, { // Test 3: An errored events run produces nothing.
		Runs:      map[string]scanner.Result{"node-health": nodes, "events": erroredRun("events")},
		WantCount: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Build([]string{"c1"}, map[string]map[string]scanner.Result{"c1": test.Runs})
			got := eventFindings(r)
			if diff := cmp.Diff(test.WantCount, len(got)); diff != "" {
				t.Fatalf("finding count mismatch (-want +got):\n%s", diff)
			}
			if len(got) == 0 {
				return
			}
			if diff := cmp.Diff(test.WantSeverity, got[0].Severity); diff != "" {
				t.Errorf("severity mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDesc, got[0].Description); diff != "" {
				t.Errorf("description mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestClusterHealthCoverage fills cluster health fields only from runs that observed them.
func TestClusterHealthCoverage(t *testing.T) {
	t.Parallel()
	results := map[string]map[string]scanner.Result{
		"c1": {
			"version":     okRun("version", map[string]any{"git_version": "v1.30.0"}),
			"node-health": degradedRun("node-health", map[string]any{"node_count": 4, "healthy_nodes": 4}),
		},
		"c2": {
			"version":     erroredRun("version"),
			"node-health": erroredRun("node-health"),
		},
	}
	r := Build([]string{"c1", "c2"}, results)
	type view struct {
		Version string
		Nodes   int
		Healthy int
	}
	got := map[string]view{}
	for _, h := range r.ClusterHealths {
		got[h.Name] = view{Version: h.KubernetesVersion, Nodes: h.NodeCount, Healthy: h.HealthyNodes}
	}
	want := map[string]view{
		// Test 0: Observed and partial fields carry their values.
		"c1": {Version: "v1.30.0", Nodes: 4, Healthy: 4},
		// Test 1: Unobserved fields stay empty.
		"c2": {},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("cluster health mismatch (-want +got):\n%s", diff)
	}
}
