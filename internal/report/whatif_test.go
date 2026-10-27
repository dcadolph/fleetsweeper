package report

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// enforcedFleet returns clusters c00 onward with the given
// security/enforced_count values.
func enforcedFleet(values ...float64) ([]string, map[string]map[string]scanner.Result) {
	clusters := make([]string, 0, len(values))
	results := make(map[string]map[string]scanner.Result, len(values))
	for i, v := range values {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{
			"security": {Scanner: "security", Data: map[string]any{"enforced_count": v}},
		}
	}
	return clusters, results
}

// TestWhatIfNumeric covers the three numeric what-if shapes: fixing the sole
// deviant leaves the median alone, and fixing or removing a deviant whose
// value holds the median moves it and exposes a new outlier.
func TestWhatIfNumeric(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Values          []float64
		Fix             Fix
		WantMedian      [2]float64
		WantMAD         [2]float64
		WantNewOutliers []string
		WantCleared     []string
	}{{ // Test 0: Ten clusters, c09 the sole deviant; the 5th and 6th values tie, so the median holds at 12.
		Values: []float64{10, 11, 11, 12, 12, 12, 13, 13, 14, 40},
		Fix:    Fix{Cluster: "c09", Scanner: "security", Field: "enforced_count"},
		// Before: deviations 2 1 1 0 0 0 1 1 2 28, MAD 1. After: 2 1 1 0 0 0 0 1 1 2, MAD 1.
		WantMedian: [2]float64{12, 12}, WantMAD: [2]float64{1, 1},
		WantCleared: []string{"c09"},
	}, { // Test 1: Ten clusters, setting c09 to the median 11.5 moves it to 11.25 and flags c08 at 14.
		Values: []float64{10, 11, 11, 11, 11, 12, 12, 13, 14, 60},
		Fix:    Fix{Cluster: "c09", Scanner: "security", Field: "enforced_count", Kind: FixMedian},
		// Before: deviations 1.5 .5 .5 .5 .5 .5 .5 1.5 2.5 48.5, MAD .5.
		// After: 10 11 11 11 11 11.5 12 12 13 14, median 11.25, deviations sorted
		// .25 .25 .25 .25 .25 .75 .75 1.25 1.75 2.75, MAD (.25+.75)/2 = .5.
		// c08 at 14: z = 0.6745 * 2.75 / .5 = 3.71, over 3.5. c07 at 13: 2.36.
		WantMedian: [2]float64{11.5, 11.25}, WantMAD: [2]float64{0.5, 0.5},
		WantNewOutliers: []string{"c08"}, WantCleared: []string{"c09"},
	}, { // Test 2: Nine clusters, removing deviant c08 moves the median from 12 to 11.5 and flags c07 at 18.
		Values: []float64{10, 11, 11, 11, 12, 14, 15, 18, 40},
		Fix:    Fix{Cluster: "c08", Scanner: "security", Field: "enforced_count", Kind: FixRemove},
		// Before: deviations 2 1 1 1 0 2 3 6 28, MAD 2, c07 z 2.02. After: eight
		// clusters, median 11.5, MAD 1, c07 z = 0.6745 * 6.5 = 4.38.
		WantMedian: [2]float64{12, 11.5}, WantMAD: [2]float64{2, 1},
		WantNewOutliers: []string{"c07"}, WantCleared: []string{"c08"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := enforcedFleet(test.Values...)
			original := results[test.Fix.Cluster]["security"].Data.(map[string]any)["enforced_count"]
			out, err := WhatIf(clusters, results, BuildOptions{}, test.Fix)
			if err != nil {
				t.Fatalf("what-if: %v", err)
			}
			if out.After == nil {
				t.Fatal("no distribution after the fix")
			}
			got := []float64{out.Before.Median, out.After.Median, out.Before.MAD, out.After.MAD,
				out.MedianShift, out.MADShift}
			want := []float64{test.WantMedian[0], test.WantMedian[1], test.WantMAD[0], test.WantMAD[1],
				test.WantMedian[1] - test.WantMedian[0], test.WantMAD[1] - test.WantMAD[0]}
			if diff := cmp.Diff(want, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("norm mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNewOutliers, out.NewOutliers, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("new outliers mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCleared, out.ClearedOutliers, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("cleared outliers mismatch (-want +got):\n%s", diff)
			}
			if len(test.WantNewOutliers) == 0 && out.ScoreAfter <= out.ScoreBefore {
				t.Errorf("score: want a rise from fixing the sole deviant, got %d -> %d", out.ScoreBefore, out.ScoreAfter)
			}
			if v := results[test.Fix.Cluster]["security"].Data.(map[string]any)["enforced_count"]; v != original {
				t.Errorf("caller's results were modified: enforced_count %v is now %v", original, v)
			}
			if len(clusters) != len(test.Values) {
				t.Errorf("caller's cluster list was modified: %v", clusters)
			}
		})
	}
}

// TestWhatIfStringAndSet covers the mode fix, which copies the norm's value and
// type, and the consensus fix on CRDs, which adds the missing objects.
func TestWhatIfStringAndSet(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()

	out, err := WhatIf(clusters, results, BuildOptions{ClusterTags: tags},
		Fix{Cluster: "c07", Scanner: "version", Field: "git_version"})
	if err != nil {
		t.Fatalf("mode fix: %v", err)
	}
	// Every cluster now runs v1.31.2, so the section is uniform and has no
	// distribution after the fix.
	if out.Fix.Kind != FixMode || out.After != nil {
		t.Errorf("mode fix: want kind mode and no distribution after, got kind %q after %+v", out.Fix.Kind, out.After)
	}
	if out.ScoreAfter <= out.ScoreBefore {
		t.Errorf("mode fix score: want a rise, got %d -> %d", out.ScoreBefore, out.ScoreAfter)
	}
	if diff := cmp.Diff([]string{"c07"}, out.ClearedOutliers); diff != "" {
		t.Errorf("mode fix cleared mismatch (-want +got):\n%s", diff)
	}

	out, err = WhatIf(clusters, results, BuildOptions{ClusterTags: tags},
		Fix{Cluster: "c09", Scanner: "crds", Field: "crd_names"})
	if err != nil {
		t.Fatalf("consensus fix: %v", err)
	}
	if diff := cmp.Diff([]string{"c09"}, out.ClearedOutliers); diff != "" {
		t.Errorf("consensus fix cleared mismatch (-want +got):\n%s", diff)
	}
	if out.ScoreAfter <= out.ScoreBefore {
		t.Errorf("consensus fix score: want a rise, got %d -> %d", out.ScoreBefore, out.ScoreAfter)
	}
}

// TestWhatIfRefusals verifies fixes that do not apply are errors, including
// the ingress-class consensus fix, which would have to invent an ingress.
func TestWhatIfRefusals(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	ingClusters := make([]string, 0, 10)
	ingResults := map[string]map[string]scanner.Result{}
	for i := range 10 {
		c := fmt.Sprintf("i%02d", i)
		class := "nginx"
		if i == 9 {
			class = "traefik"
		}
		ingClusters = append(ingClusters, c)
		ingResults[c] = map[string]scanner.Result{"ingresses": {Scanner: "ingresses", Data: map[string]any{
			"count": 1, "ingresses": []any{map[string]any{"namespace": "web", "name": "a", "ingress_class_name": class}},
		}}}
	}

	tests := []struct {
		Clusters []string
		Results  map[string]map[string]scanner.Result
		Fix      Fix
	}{{ // Test 0: A field with no distribution.
		Clusters: clusters, Results: results, Fix: Fix{Cluster: "c00", Scanner: "security", Field: "nope"},
	}, { // Test 1: A cluster outside the population.
		Clusters: clusters, Results: results, Fix: Fix{Cluster: "zz", Scanner: "security", Field: "enforced_count"},
	}, { // Test 2: A mode fix on a numeric field.
		Clusters: clusters, Results: results,
		Fix: Fix{Cluster: "c05", Scanner: "security", Field: "enforced_count", Kind: FixMode},
	}, { // Test 3: Adding an ingress class would invent an ingress.
		Clusters: ingClusters, Results: ingResults, Fix: Fix{Cluster: "i09", Scanner: "ingresses", Field: "ingress_classes"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			_, err := WhatIf(test.Clusters, test.Results, BuildOptions{ClusterTags: tags}, test.Fix)
			if !errors.Is(err, ErrWhatIf) {
				t.Errorf("want ErrWhatIf, got %v", err)
			}
		})
	}
}

// TestWhatIfRefusalReason verifies only set fields whose objects cannot be
// rebuilt from a member carry a refusal.
func TestWhatIfRefusalReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner    string
		Field      string
		WantRefuse bool
	}{{ // Test 0: Ingress classes would invent an ingress.
		Scanner: "ingresses", Field: "ingress_classes", WantRefuse: true,
	}, { // Test 1: CRD names rebuild a CRD object from the name.
		Scanner: "crds", Field: "crd_names",
	}, { // Test 2: Service names rebuild a service from namespace and name.
		Scanner: "services", Field: "service_names",
	}, { // Test 3: A numeric field on a projected scanner.
		Scanner: "ingresses", Field: "count",
	}, { // Test 4: A scanner with no projection.
		Scanner: "security", Field: "enforced_count",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := WhatIfRefusal(test.Scanner, test.Field)
			if diff := cmp.Diff(test.WantRefuse, got != ""); diff != "" {
				t.Errorf("refusal mismatch for %q (-want +got):\n%s", got, diff)
			}
		})
	}
}

// TestNoWhatIfOnFindings verifies a built report marks the ingress-class
// finding as having no what-if, and that the refusal WhatIf returns names the
// same reason the finding shows.
func TestNoWhatIfOnFindings(t *testing.T) {
	t.Parallel()
	clusters := make([]string, 0, 10)
	results := map[string]map[string]scanner.Result{}
	for i := range 10 {
		c := fmt.Sprintf("i%02d", i)
		classes := []any{map[string]any{"namespace": "web", "name": "a", "ingress_class_name": "nginx"}}
		if i == 9 {
			classes = []any{map[string]any{"namespace": "web", "name": "a", "ingress_class_name": "traefik"}}
		}
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{"ingresses": {Scanner: "ingresses", Data: map[string]any{
			"count": 1, "ingresses": classes,
		}}}
	}
	r := Build(clusters, results)
	var reason string
	for _, f := range r.Findings {
		if f.Cluster == "i09" && f.Norm != nil && f.Scanner == "ingresses" {
			reason = f.Norm.NoWhatIf
		}
	}
	if reason == "" {
		t.Fatalf("no ingress finding on i09 carries a what-if refusal: %+v", r.Findings)
	}
	_, err := WhatIf(clusters, results, BuildOptions{}, Fix{Cluster: "i09", Scanner: "ingresses", Field: "ingress_classes"})
	if !errors.Is(err, ErrWhatIf) || !strings.Contains(err.Error(), reason) {
		t.Errorf("want ErrWhatIf naming %q, got %v", reason, err)
	}
}

// TestWhatIfDefaultScope verifies an empty scope fixes toward the cluster's
// tagged cohort when that cohort has a norm for the field, and toward the
// fleet otherwise.
func TestWhatIfDefaultScope(t *testing.T) {
	t.Parallel()
	values := []float64{38, 39, 40, 40, 41, 80, 41, 42, 39, 40, 9, 10, 10, 11, 10, 9, 11, 10, 10, 12}
	tests := []struct {
		Tags       map[string]string
		WantScope  string
		WantMedian float64
	}{{ // Test 0: Tagged cohorts; c05 fixes toward the big cohort's median.
		Tags:      map[string]string{},
		WantScope: "big", WantMedian: 40,
	}, { // Test 1: No tags; c05 fixes toward the fleet median.
		WantScope: NormScopeFleet, WantMedian: 25,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := enforcedFleet(values...)
			var tags map[string]string
			if test.Tags != nil {
				tags = map[string]string{}
				for i, c := range clusters {
					tags[c] = map[bool]string{true: "big", false: "small"}[i < 10]
				}
			}
			out, err := WhatIf(clusters, results, BuildOptions{ClusterTags: tags}, Fix{Cluster: "c05", Scanner: "security", Field: "enforced_count"})
			if err != nil {
				t.Fatalf("what-if: %v", err)
			}
			if diff := cmp.Diff(test.WantScope, out.Fix.Scope); diff != "" {
				t.Errorf("scope mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantMedian, out.Before.Median); diff != "" {
				t.Errorf("median mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
