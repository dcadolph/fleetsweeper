package report

import (
	"fmt"
	"testing"
	"time"
)

// selfDriftInput builds the (scans, resultsByScan) history that DetectSelfDrift
// consumes from a single scanner field's value series, oldest first.
func selfDriftInput(scanner, field string, values []float64) ([]ScanMeta, map[string]map[string]map[string]any) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scans := make([]ScanMeta, len(values))
	results := make(map[string]map[string]map[string]any, len(values))
	for i, v := range values {
		id := fmt.Sprintf("scan-%02d", i)
		scans[i] = ScanMeta{ID: id, Timestamp: base.Add(time.Duration(i) * time.Hour)}
		results[id] = map[string]map[string]any{scanner: {field: v}}
	}
	return scans, results
}

func TestDetectSelfDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name          string
		Values        []float64
		WantCount     int
		WantDirection TrendDirection
		WantChangeIdx int
	}{{ // Test 0: a flat baseline that steps up is a worsening self-drift.
		Name:          "step up",
		Values:        []float64{10, 10, 10, 10, 10, 50, 50, 50},
		WantCount:     1,
		WantDirection: TrendWorsening,
		WantChangeIdx: 5,
	}, { // Test 1: a step down on an up-is-bad metric is improving.
		Name:          "step down",
		Values:        []float64{80, 82, 78, 81, 79, 20, 22, 21},
		WantCount:     1,
		WantDirection: TrendImproving,
		WantChangeIdx: 5,
	}, { // Test 2: noisy but level history is not flagged.
		Name:      "stable noise",
		Values:    []float64{40, 42, 38, 41, 39, 40, 41, 39},
		WantCount: 0,
	}, { // Test 3: too little history yields nothing.
		Name:      "short",
		Values:    []float64{10, 10, 60},
		WantCount: 0,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			scans, results := selfDriftInput("metrics", "avg_cpu_percent", test.Values)
			got := DetectSelfDrift("prod-east", scans, results)

			if len(got) != test.WantCount {
				t.Fatalf("%s: got %d drifts, want %d: %+v", test.Name, len(got), test.WantCount, got)
			}
			if test.WantCount == 0 {
				return
			}
			d := got[0]
			if d.Direction != test.WantDirection {
				t.Errorf("%s: direction = %q, want %q", test.Name, d.Direction, test.WantDirection)
			}
			if d.Cluster != "prod-east" || d.Scanner != "metrics" || d.Field != "avg_cpu_percent" {
				t.Errorf("%s: identity = %s/%s/%s", test.Name, d.Cluster, d.Scanner, d.Field)
			}
			wantChangedAt := scans[test.WantChangeIdx].Timestamp
			if !d.ChangedAt.Equal(wantChangedAt) {
				t.Errorf("%s: ChangedAt = %s, want %s", test.Name, d.ChangedAt, wantChangedAt)
			}
		})
	}
}

// TestSelfDriftFindings verifies a detected shift becomes a finding carrying the
// cluster, scanner, and calibrated severity.
func TestSelfDriftFindings(t *testing.T) {
	t.Parallel()

	drifts := []SelfDrift{{
		Cluster: "prod-east", Scanner: "metrics", Field: "avg_cpu_percent",
		Baseline: 10, Latest: 50, Deviation: 4,
		ChangedAt: time.Date(2026, 1, 1, 5, 0, 0, 0, time.UTC),
		Direction: TrendWorsening, Severity: SeverityWarning,
	}}

	got := SelfDriftFindings(drifts)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Cluster != "prod-east" || got[0].Scanner != "metrics" || got[0].Severity != SeverityWarning {
		t.Errorf("finding = %+v", got[0])
	}
}
