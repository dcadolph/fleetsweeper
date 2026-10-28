package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

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
	for i := range 50 {
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

// goldenFlat builds the flat per-cluster shape the detectors consume, one
// cluster per value under the field "f".
func goldenFlat(values []any) ([]string, map[string]map[string]any) {
	clusters := make([]string, len(values))
	flat := make(map[string]map[string]any, len(values))
	for i, v := range values {
		c := fmt.Sprintf("c%02d", i)
		clusters[i] = c
		flat[c] = map[string]any{"f": v}
	}
	return clusters, flat
}

// floats converts numbers to the any slice goldenFlat takes.
func floats(vs ...float64) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

// repeat returns n copies of v.
func repeat(v any, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// join concatenates value slices.
func join(parts ...[]any) []any {
	var out []any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestDetectNumericOutliersGolden checks hand-computed medians, MADs, and
// modified z-scores against the numeric detector.
func TestDetectNumericOutliersGolden(t *testing.T) {
	t.Parallel()

	// Runtime values so the boundary threshold matches the code's float math.
	boundary := 0.6745 * (40.0 - 11.5) / 1.0

	tests := []struct {
		Name        string
		Values      []any
		Threshold   float64
		WantResults []OutlierResult
	}{{ // Test 0: Median 11.5, MAD 1.0, only the 40 is flagged.
		Name:      "classic single outlier",
		Values:    floats(10, 10, 11, 11, 12, 12, 13, 40),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c07", Field: "f", Value: "40", FleetNorm: "11.5",
			Deviation: 19.22, Scanner: "metrics", Severity: SeverityInfo,
			Kind: NormKindNumeric, Median: 11.5, MAD: 1.0, SampleSize: 8, Threshold: 3.5, Z: 19.22,
		}},
	}, { // Test 1: Modified z exactly at the threshold is not flagged.
		Name:      "z equal to threshold",
		Values:    floats(10, 10, 11, 11, 12, 12, 13, 40),
		Threshold: boundary,
	}, { // Test 2: Threshold just below the modified z flags the value.
		Name:      "z just above threshold",
		Values:    floats(10, 10, 11, 11, 12, 12, 13, 40),
		Threshold: boundary - 0.01,
		WantResults: []OutlierResult{{
			Cluster: "c07", Field: "f", Value: "40", FleetNorm: "11.5",
			Deviation: 19.22, Scanner: "metrics", Severity: SeverityInfo,
			Kind: NormKindNumeric, Median: 11.5, MAD: 1.0, SampleSize: 8, Threshold: boundary - 0.01, Z: 19.22,
		}},
	}, { // Test 3: Median 100, MAD 10, value 151.5 gives z 3.47, not flagged.
		Name:      "z 3.47 below 3.5",
		Values:    floats(90, 90, 90, 100, 100, 110, 110, 110, 151.5),
		Threshold: 3.5,
	}, { // Test 4: Median 100, MAD 10, value 152.04 gives z 3.51, flagged.
		Name:      "z 3.51 above 3.5",
		Values:    floats(90, 90, 90, 100, 100, 110, 110, 110, 152.04),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c08", Field: "f", Value: "152.0", FleetNorm: "100",
			Deviation: 3.51, Scanner: "metrics", Severity: SeverityInfo,
			Kind: NormKindNumeric, Median: 100, MAD: 10, SampleSize: 9, Threshold: 3.5, Z: 3.51,
		}},
	}, { // Test 5: Seven values are below the sample floor.
		Name:      "n equals 7",
		Values:    floats(10, 10, 11, 11, 12, 12, 40),
		Threshold: 3.5,
	}, { // Test 6: Eight values reach the sample floor and emit.
		Name:      "n equals 8",
		Values:    floats(10, 10, 11, 11, 12, 12, 13, 40),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c07", Field: "f", Value: "40", FleetNorm: "11.5",
			Deviation: 19.22, Scanner: "metrics", Severity: SeverityInfo,
			Kind: NormKindNumeric, Median: 11.5, MAD: 1.0, SampleSize: 8, Threshold: 3.5, Z: 19.22,
		}},
	}, { // Test 7: 49 identical and 1 different has MAD 0, so the one off the median is exact.
		Name:      "zero MAD exact",
		Values:    join(repeat(float64(5), 49), floats(500)),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c49", Field: "f", Value: "500", FleetNorm: "5", Scanner: "metrics",
			Severity: SeverityInfo, Kind: NormKindNumeric, Median: 5, ModeShare: 0.98,
			SampleSize: 50, Threshold: minStringModeMass, Exact: true,
		}},
	}, { // Test 8: Even n averages the middle pair, 20 vs median 5.5 is flagged.
		Name:      "even n median",
		Values:    floats(4, 4, 5, 5, 6, 6, 7, 20),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c07", Field: "f", Value: "20", FleetNorm: "5.5",
			Deviation: 0.6745 * 14.5 / 1.0, Scanner: "metrics", Severity: SeverityInfo,
			Kind: NormKindNumeric, Median: 5.5, MAD: 1.0, SampleSize: 8, Threshold: 3.5, Z: 0.6745 * 14.5 / 1.0,
		}},
	}, { // Test 9: Nine zeros and one 3 flag the 3 as exact.
		Name:      "nine zeros one three",
		Values:    join(repeat(float64(0), 9), floats(3)),
		Threshold: 3.5,
		WantResults: []OutlierResult{{
			Cluster: "c09", Field: "f", Value: "3", FleetNorm: "0", Scanner: "metrics",
			Severity: SeverityInfo, Kind: NormKindNumeric, ModeShare: 0.9, SampleSize: 10,
			Threshold: minStringModeMass, Exact: true,
		}},
	}, { // Test 10: Six ones and five zeros hold the median 1 at 6/11, under 0.6, so nothing flags.
		Name:      "six and five",
		Values:    join(repeat(float64(0), 5), repeat(float64(1), 6)),
		Threshold: 3.5,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			clusters, flat := goldenFlat(test.Values)
			got, _ := detectNumericOutliers(clusters, flat, "f", "metrics", test.Threshold)
			opts := []cmp.Option{
				cmpopts.EquateApprox(0, 0.01),
				cmpopts.EquateEmpty(),
				cmpopts.SortSlices(func(a, b OutlierResult) bool { return a.Cluster < b.Cluster }),
			}
			if diff := cmp.Diff(test.WantResults, got, opts...); diff != "" {
				t.Errorf("results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestComputeMedianMAD checks the median and MAD helpers on hand-computed data.
func TestComputeMedianMAD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Values     []float64
		WantMedian float64
		WantMAD    float64
	}{{ // Test 0: Even count averages the middle pair.
		Values: []float64{10, 10, 11, 11, 12, 12, 13, 40}, WantMedian: 11.5, WantMAD: 1.0,
	}, { // Test 1: Odd count takes the middle value.
		Values: []float64{1, 2, 3, 4, 100}, WantMedian: 3, WantMAD: 1,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			med := computeMedian(test.Values)
			if diff := cmp.Diff(test.WantMedian, med, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("median mismatch (-want +got):\n%s", diff)
			}
			mad := computeMAD(test.Values, med)
			if diff := cmp.Diff(test.WantMAD, mad, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("MAD mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetectStringOutliersGolden checks the mode-mass guard and flagging.
func TestDetectStringOutliersGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		Values       []any
		WantClusters []string
	}{{ // Test 0: A three-way tie emits nothing.
		Name:   "three-way tie",
		Values: join(repeat("a", 4), repeat("b", 4), repeat("c", 4)),
	}, { // Test 1: A 59/41 split is under the 60% mode mass and emits nothing.
		Name:   "59/41 split",
		Values: join(repeat("a", 59), repeat("b", 41)),
	}, { // Test 2: A 70/30 split flags the 30 minority clusters.
		Name:   "70/30 split",
		Values: join(repeat("a", 70), repeat("b", 30)),
		WantClusters: func() []string {
			var cs []string
			for i := 70; i < 100; i++ {
				cs = append(cs, fmt.Sprintf("c%02d", i))
			}
			return cs
		}(),
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			clusters, flat := goldenFlat(test.Values)
			got, _ := detectStringOutliers(clusters, flat, "f", "version")
			var gotClusters []string
			for _, o := range got {
				if o.Value != "b" || o.FleetNorm != "a" {
					t.Errorf("unexpected finding %+v", o)
				}
				gotClusters = append(gotClusters, o.Cluster)
			}
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.SortSlices(func(a, b string) bool { return a < b }),
			}
			if diff := cmp.Diff(test.WantClusters, gotClusters, opts...); diff != "" {
				t.Errorf("clusters mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetectSetOutliersGolden checks the 60% consensus rule for array fields.
func TestDetectSetOutliersGolden(t *testing.T) {
	t.Parallel()

	with := []any{"x"}
	without := []any{"y"}

	tests := []struct {
		Name        string
		Values      []any
		WantResults []OutlierResult
	}{{ // Test 0: 8 of 10 hold x, so the 2 without it are flagged.
		Name:   "8 of 10 consensus",
		Values: join(repeat(with, 8), repeat(without, 2)),
		WantResults: []OutlierResult{{
			Cluster: "c08", Field: "f", Value: "missing 1: [x]",
			FleetNorm: "1 consensus items", Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
			Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6,
		}, {
			Cluster: "c09", Field: "f", Value: "missing 1: [x]",
			FleetNorm: "1 consensus items", Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
			Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6,
		}},
	}, { // Test 1: 6 of 10 meets the 60% consensus, so the other 4 are flagged.
		Name:   "6 of 10 is consensus",
		Values: join(repeat(with, 6), repeat(without, 4)),
		WantResults: []OutlierResult{
			{Cluster: "c06", Field: "f", Value: "missing 1: [x]", FleetNorm: "1 consensus items",
				Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
				Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6},
			{Cluster: "c07", Field: "f", Value: "missing 1: [x]", FleetNorm: "1 consensus items",
				Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
				Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6},
			{Cluster: "c08", Field: "f", Value: "missing 1: [x]", FleetNorm: "1 consensus items",
				Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
				Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6},
			{Cluster: "c09", Field: "f", Value: "missing 1: [x]", FleetNorm: "1 consensus items",
				Scanner: "pods", Severity: SeverityInfo, Kind: NormKindSet,
				Consensus: []string{"x"}, Missing: []string{"x"}, SampleSize: 10, Threshold: 0.6},
		},
	}, { // Test 2: 5 of 10 is below consensus, so nothing is flagged.
		Name:   "5 of 10 is not consensus",
		Values: join(repeat(with, 5), repeat(without, 5)),
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			clusters, flat := goldenFlat(test.Values)
			got, _ := detectSetOutliers(clusters, flat, "f", "pods")
			opts := []cmp.Option{
				cmpopts.EquateEmpty(),
				cmpopts.SortSlices(func(a, b OutlierResult) bool { return a.Cluster < b.Cluster }),
			}
			if diff := cmp.Diff(test.WantResults, got, opts...); diff != "" {
				t.Errorf("results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNumericSeverityDirection verifies a numeric outlier on the better side of a field with
// a polarity is info and favorable, on the worse side keeps the field's severity, and on a
// field with no polarity keeps it in both directions, for the MAD and majority detectors.
func TestNumericSeverityDirection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner       string
		Field         string
		WantSeverity  string
		WantTitle     string
		WantNote      string
		Vals          []any
		WantFavorable bool
	}{{ // Test 0: Fewer privileged containers than a fleet of nine is info and favorable.
		Scanner: "workload-security", Field: "privileged_containers",
		Vals:         []any{5, 6, 7, 6, 5, 7, 6, 6, 0},
		WantSeverity: SeverityInfo, WantFavorable: true,
		WantTitle: "c08 is better than the fleet norm on privileged_containers",
		WantNote:  "Lower is better for this field",
	}, { // Test 1: More unhealthy nodes than a fleet of nine is critical.
		Scanner: "node-health", Field: "unhealthy_nodes",
		Vals:         []any{5, 6, 7, 6, 5, 7, 6, 6, 30},
		WantSeverity: SeverityCritical,
		WantTitle:    "c08 deviates from fleet norm on unhealthy_nodes",
	}, { // Test 2: A namespace count far below the fleet is a warning.
		Scanner: "namespaces", Field: "count",
		Vals:         []any{20, 22, 24, 24, 24, 26, 26, 28, 2},
		WantSeverity: SeverityWarning,
		WantTitle:    "c08 deviates from fleet norm on count",
	}, { // Test 3: A namespace count far above the fleet is a warning.
		Scanner: "namespaces", Field: "count",
		Vals:         []any{20, 22, 24, 24, 24, 26, 26, 28, 80},
		WantSeverity: SeverityWarning,
		WantTitle:    "c08 deviates from fleet norm on count",
	}, { // Test 4: More enforced namespaces in a fleet of five is info and favorable.
		Scanner: "security", Field: "enforced_count",
		Vals:         []any{10, 11, 10, 11, 40},
		WantSeverity: SeverityInfo, WantFavorable: true,
		WantTitle: "c04 is better than the fleet norm on enforced_count",
		WantNote:  "Higher is better for this field",
	}, { // Test 5: Fewer enforced namespaces in a fleet of five is critical capped at warning.
		Scanner: "security", Field: "enforced_count",
		Vals:         []any{10, 11, 10, 11, 1},
		WantSeverity: SeverityWarning,
		WantTitle:    "c04 deviates from fleet norm on enforced_count",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := fieldFleet(test.Scanner, test.Field, test.Vals...)
			r := Build(clusters, results)
			if len(r.Outliers) != 1 {
				t.Fatalf("want one outlier, got %+v", r.Outliers)
			}
			o := r.Outliers[0]
			if diff := cmp.Diff(test.WantSeverity+fmt.Sprint(test.WantFavorable),
				o.Severity+fmt.Sprint(o.Favorable)); diff != "" {
				t.Errorf("severity and favorable mismatch (-want +got):\n%s", diff)
			}
			got := outlierRuleFindings(r, fieldRule(test.Scanner, ruleOutlierPrefix, test.Field))
			if len(got) != 1 {
				t.Fatalf("want one outlier finding, got %+v", got)
			}
			if diff := cmp.Diff(test.WantTitle, got[0].Title); diff != "" {
				t.Errorf("title mismatch (-want +got):\n%s", diff)
			}
			if got[0].Severity != test.WantSeverity {
				t.Errorf("finding severity = %s, want %s", got[0].Severity, test.WantSeverity)
			}
			if hasNote := strings.Contains(got[0].Description, "is better for this field"); hasNote !=
				(test.WantNote != "") || !strings.Contains(got[0].Description, test.WantNote) {
				t.Errorf("description %q, want note %q", got[0].Description, test.WantNote)
			}
		})
	}
}

// TestExactNorms verifies a zero-MAD numeric field is judged by mode share through Build:
// direction-aware severity, an exact distribution with no band, the remediation wording, and
// the majority path with no sentinel.
func TestExactNorms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner       string
		Field         string
		WantCluster   string
		WantSeverity  string
		WantGap       string
		Vals          []any
		WantShare     float64
		WantFavorable bool
	}{{ // Test 0: Twelve privileged containers in a fleet of zeros is critical and exact.
		Scanner: "workload-security", Field: "privileged_containers",
		Vals:        []any{0, 0, 0, 0, 0, 0, 0, 0, 12},
		WantCluster: "c08", WantSeverity: SeverityCritical, WantShare: 8.0 / 9,
		WantGap: "privileged_containers is 12 here, every other cluster in the fleet reports exactly 0",
	}, { // Test 1: Zero privileged containers in a fleet of sixes is info and favorable.
		Scanner: "workload-security", Field: "privileged_containers",
		Vals:        []any{6, 6, 6, 6, 6, 6, 6, 6, 0},
		WantCluster: "c08", WantSeverity: SeverityInfo, WantShare: 8.0 / 9, WantFavorable: true,
		WantGap: "privileged_containers is 0 here, every other cluster in the fleet reports exactly 6",
	}, { // Test 2: A fleet of five with four 2s and one 7 is exact through the majority diff.
		Scanner: "novel", Field: "count",
		Vals:        []any{2, 2, 7, 2, 2},
		WantCluster: "c02", WantSeverity: SeverityInfo, WantShare: 0.8,
		WantGap: "count is 7 here, every other cluster in the fleet reports exactly 2",
	}, { // Test 3: One not-ready node in a fleet of ten zeros is critical and exact.
		Scanner: "node-health", Field: "not_ready_nodes",
		Vals:        []any{0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		WantCluster: "c08", WantSeverity: SeverityCritical, WantShare: 0.9,
		WantGap: "not_ready_nodes is 1 here, every other cluster in the fleet reports exactly 0",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := fieldFleet(test.Scanner, test.Field, test.Vals...)
			r := Build(clusters, results)
			if len(r.Outliers) != 1 {
				t.Fatalf("want one outlier, got %+v", r.Outliers)
			}
			o := r.Outliers[0]
			got := fmt.Sprint(o.Cluster, " ", o.Severity, " ", o.Favorable, " ", o.Exact, " ", o.Z, " ",
				o.Deviation)
			want := fmt.Sprint(test.WantCluster, " ", test.WantSeverity, " ", test.WantFavorable,
				" true 0 0")
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("outlier mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantShare, o.ModeShare, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("share mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantGap, normGap(o, NormScopeFleet)); diff != "" {
				t.Errorf("gap mismatch (-want +got):\n%s", diff)
			}
			var dist *Distribution
			for i := range r.Distributions {
				if r.Distributions[i].Field == test.Field && r.Distributions[i].Scope == NormScopeFleet {
					dist = &r.Distributions[i]
				}
			}
			if dist == nil || !dist.Exact || dist.Band != 0 {
				t.Fatalf("want an exact fleet distribution with no band, got %+v", dist)
			}
			for _, f := range r.Findings {
				if f.Norm != nil && f.Cluster == test.WantCluster && !f.Norm.Exact {
					t.Errorf("finding %s norm is not exact: %+v", f.Rule, f.Norm)
				}
			}
		})
	}
}

// TestExactNormPhrase verifies an exact norm is worded as who holds it.
func TestExactNormPhrase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantResult string
		Share      float64
		N          int
	}{{ // Test 0: One cluster off the norm reads as every other cluster.
		Share: 0.9, N: 10, WantResult: "every other cluster in the fleet reports exactly 0",
	}, { // Test 1: Two clusters off the norm state the count.
		Share: 0.8, N: 10, WantResult: "8 of 10 clusters in the fleet report exactly 0",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, exactNormPhrase(test.Share, test.N, "0", "the fleet")); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
