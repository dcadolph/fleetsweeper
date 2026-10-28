package report

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// fieldFleet returns clusters c00, c01, ... and scanner results that give each
// cluster one field on one scanner, taken in order from vals.
func fieldFleet(scannerName, field string, vals ...any) ([]string, map[string]map[string]scanner.Result) {
	clusters := make([]string, 0, len(vals))
	results := make(map[string]map[string]scanner.Result, len(vals))
	for i, v := range vals {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{scannerName: {Data: map[string]any{field: v}}}
	}
	return clusters, results
}

// outlierRuleFindings returns the findings whose rule is rule.
func outlierRuleFindings(r *Report, rule string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// TestSmallFleetBuild verifies Build picks the outlier detector by fleet size:
// MAD from minMADSample clusters, the majority diff below that, and a note
// below minMajoritySample.
func TestSmallFleetBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name             string
		Scanner          string
		Vals             []any
		WantClusters     []string
		WantLimited      bool
		WantSeverity     string
		WantNote         bool
		WantFindingCount int
	}{{ // Test 0: Ten clusters reach the MAD floor and flag the deviant.
		Name: "10 clusters MAD", Scanner: "novel",
		Vals:         []any{20, 22, 24, 24, 24, 26, 26, 28, 30, 80},
		WantClusters: []string{"c09"}, WantSeverity: SeverityInfo, WantFindingCount: 1,
	}, { // Test 1: Five clusters with one deviant emit a limited-sample finding.
		Name: "5 clusters one deviant", Scanner: "novel",
		Vals:         []any{10, 11, 10, 11, 40},
		WantClusters: []string{"c04"}, WantLimited: true, WantSeverity: SeverityInfo, WantFindingCount: 1,
	}, { // Test 2: Five clusters with two deviants emit nothing.
		Name: "5 clusters two deviants", Scanner: "novel",
		Vals: []any{10, 11, 10, 40, 50},
	}, { // Test 3: A critical field is capped at warning under a limited sample.
		Name: "severity cap", Scanner: "security",
		Vals:         []any{10, 11, 10, 11, 40},
		WantClusters: []string{"c04"}, WantLimited: true, WantSeverity: SeverityWarning, WantFindingCount: 1,
	}, { // Test 4: Two clusters emit nothing and explain why.
		Name: "2 clusters", Scanner: "novel",
		Vals: []any{10, 40}, WantNote: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			field := "count"
			if test.Scanner == "security" {
				field = "unenforced_count"
			}
			clusters, results := fieldFleet(test.Scanner, field, test.Vals...)
			r := Build(clusters, results)

			var gotClusters []string
			for _, o := range r.Outliers {
				gotClusters = append(gotClusters, o.Cluster)
				if o.LimitedSample != test.WantLimited {
					t.Errorf("%s limited_sample = %v, want %v", o.Cluster, o.LimitedSample, test.WantLimited)
				}
				if o.Severity != test.WantSeverity {
					t.Errorf("%s severity = %s, want %s", o.Cluster, o.Severity, test.WantSeverity)
				}
			}
			if diff := cmp.Diff(test.WantClusters, gotClusters, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("outlier clusters mismatch (-want +got):\n%s", diff)
			}

			got := outlierRuleFindings(r, fieldRule(test.Scanner, ruleOutlierPrefix, field))
			if len(got) != test.WantFindingCount {
				t.Fatalf("want %d outlier findings, got %d: %+v", test.WantFindingCount, len(got), got)
			}
			for _, f := range got {
				if f.Norm == nil || f.Norm.LimitedSample != test.WantLimited {
					t.Errorf("finding norm %+v, want limited_sample %v", f.Norm, test.WantLimited)
				}
			}

			wantNote := "Fleet-relative outlier detection needs at least 3 clusters; this report has 2."
			if got := slices.Contains(r.Notes, wantNote); got != test.WantNote {
				t.Errorf("notes %q contain %q = %v, want %v", r.Notes, wantNote, got, test.WantNote)
			}
		})
	}
}

// TestSmallFleetCohorts verifies a tagged cohort of 3 to 7 clusters runs the
// majority diff against its own peers when the fleet-wide norm hides the
// deviant.
func TestSmallFleetCohorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		Edge         []any
		WantClusters []string
	}{{ // Test 0: One deviant in a cohort of 6 is a limited-sample cohort finding.
		Name: "one deviant", Edge: []any{10, 10, 10, 10, 10, 30}, WantClusters: []string{"c05"},
	}, { // Test 1: Two deviants in a cohort of 6 emit nothing.
		Name: "two deviants", Edge: []any{10, 10, 10, 10, 30, 40},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			// The core cohort spreads 100 to 105, so no core member has
			// agreeing peers, and the fleet median of 12 values sits between
			// the cohorts, so the fleet MAD flags nothing.
			vals := append(slices.Clone(test.Edge), 100, 101, 102, 103, 104, 105)
			clusters, results := fieldFleet("novel", "count", vals...)
			tags := make(map[string]string, len(clusters))
			for i, c := range clusters {
				tags[c] = "core"
				if i < len(test.Edge) {
					tags[c] = "edge"
				}
			}
			r := Build(clusters, results, BuildOptions{ClusterTags: tags})
			if len(r.Outliers) != 0 {
				t.Fatalf("fixture must hide the deviant from the fleet norm, got %+v", r.Outliers)
			}

			var gotClusters []string
			for _, f := range outlierRuleFindings(r, fieldRule("novel", ruleCohortOutlierPrefix, "count")) {
				gotClusters = append(gotClusters, f.Cluster)
				if f.Norm == nil || !f.Norm.LimitedSample || f.Norm.Scope != "edge" {
					t.Errorf("cohort finding norm %+v, want limited_sample in scope edge", f.Norm)
				}
			}
			if diff := cmp.Diff(test.WantClusters, gotClusters, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("cohort finding clusters mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMajorityNumericOutlier checks the leave-one-out rule on hand-computed
// populations.
func TestMajorityNumericOutlier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name       string
		Vals       []any
		WantResult *OutlierResult
	}{{ // Test 0: For 10, 12, 30 only 30 qualifies: peers 10 and 12 give
		// median 11, MAD 1, z = 0.6745 * 19 = 12.8155. For 10, peers 12 and
		// 30 give median 21, MAD 9, z = 0.6745 * -11 / 9 = -0.82.
		Name: "three clusters", Vals: []any{10, 12, 30},
		WantResult: &OutlierResult{
			Cluster: "c02", Value: "30", FleetNorm: "11", Deviation: 12.8155,
			Kind: NormKindNumeric, Median: 11, MAD: 1, SampleSize: 3, Threshold: 3.5, Z: 12.8155,
		},
	}, { // Test 1: Identical peers make any difference count, with z capped.
		Name: "zero MAD peers", Vals: []any{10, 10, 10, 10, 11},
		WantResult: &OutlierResult{
			Cluster: "c04", Value: "11", FleetNorm: "10", Deviation: maxReportedDeviation,
			Kind: NormKindNumeric, Median: 10, MAD: 0, SampleSize: 5, Threshold: 3.5, Z: maxReportedDeviation,
		},
	}, { // Test 2: A low deviant gets a negative z: peers 50 50 51 51 give
		// median 50.5, MAD 0.5, z = 0.6745 * -48.5 / 0.5 = -65.4265.
		Name: "low deviant", Vals: []any{50, 51, 2, 50, 51},
		WantResult: &OutlierResult{
			Cluster: "c02", Value: "2", FleetNorm: "50.5", Deviation: 65.4265,
			Kind: NormKindNumeric, Median: 50.5, MAD: 0.5, SampleSize: 5, Threshold: 3.5, Z: -65.4265,
		},
	}, { // Test 3: Peers 10 10 12 12 agree, but 14 is only z 2.02 from them.
		Name: "below threshold", Vals: []any{10, 10, 12, 12, 14},
	}, { // Test 4: Peers that do not agree among themselves give no norm.
		Name: "peers disagree", Vals: []any{10, 11, 13, 17, 40},
	}, { // Test 5: Every value equal has nothing to flag.
		Name: "uniform", Vals: []any{7, 7, 7, 7},
	}, { // Test 6: Two values are below the majority floor.
		Name: "two values", Vals: []any{10, 40},
	}, { // Test 7: Eight values belong to MAD, not the majority diff.
		Name: "eight values", Vals: []any{10, 10, 10, 10, 10, 10, 10, 40},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			clusters, flat := goldenFlat(test.Vals)
			got := majorityNumericOutlier(clusters, flat, "f", 3.5)
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMajorityStringOutlier checks the string majority rule.
func TestMajorityStringOutlier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Vals       []any
		WantResult *OutlierResult
	}{{ // Test 0: Four peers on one value flag the fifth.
		Vals: []any{"a", "a", "b", "a", "a"},
		WantResult: &OutlierResult{
			Cluster: "c02", Value: "b", FleetNorm: "a",
			Kind: NormKindString, Mode: "a", ModeShare: 0.8, SampleSize: 5, Threshold: 0.8,
		},
	}, { // Test 1: A 3 to 2 split has no single deviant.
		Vals: []any{"a", "a", "a", "b", "b"},
	}, { // Test 2: Three distinct values have no majority.
		Vals: []any{"a", "a", "b", "c"},
	}, { // Test 3: A missing field is not a value.
		Vals: []any{"a", "a", "a", nil},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, flat := goldenFlat(test.Vals)
			if diff := cmp.Diff(test.WantResult, majorityStringOutlier(clusters, flat, "f")); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
