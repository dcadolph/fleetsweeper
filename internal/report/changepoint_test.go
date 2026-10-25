package report

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

// TestDetectSelfDriftGolden pins Baseline, Latest, Deviation, and Severity with
// values computed by hand. A baseline of [8,9,10,11,12] has median 10 and MAD 1,
// so a recent value x has modified z 0.6745*(x-10).
func TestDetectSelfDriftGolden(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	tests := []struct {
		Name          string
		Values        []float64
		WantChangeIdx int
		WantDrifts    []SelfDrift
	}{{ // Test 0: x=15.18 gives z 0.6745*5.18=3.4939, under 3.5, not flagged.
		Name:   "z just under threshold",
		Values: []float64{8, 9, 10, 11, 12, 15.18},
	}, { // Test 1: x=15.2 gives z 0.6745*5.2=3.5074, over 3.5, flagged as worsening.
		Name:          "z just over threshold",
		Values:        []float64{8, 9, 10, 11, 12, 15.2},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 10, Latest: 15.2, Deviation: 3.5074,
			Direction: TrendWorsening, Severity: SeverityWarning,
		}},
	}, { // Test 2: x=4 gives z 0.6745*-6=-4.047, a fall on an up-is-bad metric is improving.
		Name:          "improving step",
		Values:        []float64{8, 9, 10, 11, 12, 4},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 10, Latest: 4, Deviation: 4.047,
			Direction: TrendImproving, Severity: SeverityInfo,
		}},
	}, { // Test 3: Recent segment [20,22,24] has mean 22, z 0.6745*12=8.094. The split
		// score at k=5 is sqrt(15/8)*12=16.43, above k=6 (13.88) and k=7 (10.16).
		Name:          "recent segment uses the mean",
		Values:        []float64{8, 9, 10, 11, 12, 20, 22, 24},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 10, Latest: 22, Deviation: 8.094,
			Direction: TrendWorsening, Severity: SeverityWarning,
		}},
	}, { // Test 4: Flat baseline 10, x=14.9 is a step of 0.49, under 0.5, not flagged.
		Name:   "flat step under relative floor",
		Values: []float64{10, 10, 10, 10, 10, 14.9},
	}, { // Test 5: Flat baseline 10, x=15 is a step of 5/10=0.5, at the floor, flagged.
		Name:          "flat step at relative floor",
		Values:        []float64{10, 10, 10, 10, 10, 15},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 10, Latest: 15, Deviation: 0.5,
			Direction: TrendWorsening, Severity: SeverityWarning,
		}},
	}, { // Test 6: Flat zero baseline divides by max(|0|,1)=1, so 0.4 is under 0.5.
		Name:   "zero baseline small step",
		Values: []float64{0, 0, 0, 0, 0, 0.4},
	}, { // Test 7: Flat zero baseline, 0.6 is a step of 0.6, flagged.
		Name:          "zero baseline step",
		Values:        []float64{0, 0, 0, 0, 0, 0.6},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 0, Latest: 0.6, Deviation: 0.6,
			Direction: TrendWorsening, Severity: SeverityWarning,
		}},
	}, { // Test 8: A change at index 4 is never reported there; the earliest split is 5.
		// Baseline [10,10,10,10,50] has median 10 and MAD 0, step (50-10)/10=4.
		Name:          "change at index 4 attributed to 5",
		Values:        []float64{10, 10, 10, 10, 50, 50},
		WantChangeIdx: 5,
		WantDrifts: []SelfDrift{{
			Baseline: 10, Latest: 50, Deviation: 4,
			Direction: TrendWorsening, Severity: SeverityWarning,
		}},
	}, { // Test 9: Five points are under the six-point sample floor.
		Name:   "under sample floor",
		Values: []float64{10, 10, 10, 10, 50},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			scans, results := selfDriftInput("metrics", "avg_cpu_percent", test.Values)
			got := DetectSelfDrift("prod-east", scans, results)
			want := test.WantDrifts
			for i := range want {
				want[i].Cluster = "prod-east"
				want[i].Scanner = "metrics"
				want[i].Field = "avg_cpu_percent"
				want[i].ChangedAt = scans[test.WantChangeIdx].Timestamp
			}
			opts := []cmp.Option{cmpopts.EquateApprox(0, 0.001), cmpopts.EquateEmpty()}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("drift mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
