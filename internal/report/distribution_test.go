package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// distributionFleet builds a 12-cluster fleet, c00 to c11, tagged into two
// cohorts of six. c05 runs far more enforced namespaces than anyone, c07 runs
// an older version, c09 lacks a CRD the rest have, and quota_count differs on
// one cluster only, so its MAD is zero.
func distributionFleet() ([]string, map[string]map[string]scanner.Result, map[string]string) {
	enforced := []float64{20, 22, 24, 24, 24, 80, 26, 26, 28, 30, 25, 23}
	clusters := make([]string, 0, len(enforced))
	results := make(map[string]map[string]scanner.Result, len(enforced))
	tags := make(map[string]string, len(enforced))
	for i, e := range enforced {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		version := "v1.31.2"
		if c == "c07" {
			version = "v1.29.0"
		}
		quota := 6
		if c == "c03" {
			quota = 9
		}
		crds := []any{
			map[string]any{"name": "certificates.cert-manager.io"},
			map[string]any{"name": "issuers.cert-manager.io"},
		}
		if c == "c09" {
			crds = crds[:1]
		}
		results[c] = map[string]scanner.Result{
			"security":        {Scanner: "security", Data: map[string]any{"enforced_count": e}},
			"version":         {Scanner: "version", Data: map[string]any{"git_version": version}},
			"resource-quotas": {Scanner: "resource-quotas", Data: map[string]any{"quota_count": quota}},
			"crds":            {Scanner: "crds", Data: map[string]any{"count": len(crds), "crds": crds}},
		}
		tags[c] = "east"
		if i >= 6 {
			tags[c] = "west"
		}
	}
	return clusters, results, tags
}

// findDistribution returns the distribution for scope, scanner, and field.
func findDistribution(t *testing.T, r *Report, scope, scannerName, field string) Distribution {
	t.Helper()
	for _, d := range r.Distributions {
		if d.Scope == scope && d.Scanner == scannerName && d.Field == field {
			return d
		}
	}
	t.Fatalf("no %s distribution for %s/%s", scope, scannerName, field)
	return Distribution{}
}

// flaggedKey names one flagged cluster value: scope, scanner, field, cluster.
type flaggedKey struct {
	// Scope is the norm scope.
	Scope string
	// Scanner is the scanner name.
	Scanner string
	// Field is the field name.
	Field string
	// Cluster is the flagged cluster.
	Cluster string
}

// TestDistributionsMatchDetectors verifies that every outlier the fleet and
// cohort detectors report is flagged in its distribution and nothing else is,
// and that each outlier's norm equals its distribution's.
func TestDistributionsMatchDetectors(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	r := Build(clusters, results, BuildOptions{ClusterTags: tags})

	fromOutliers := map[flaggedKey]OutlierResult{}
	for _, o := range r.Outliers {
		fromOutliers[flaggedKey{o.Scope, o.Scanner, o.Field, o.Cluster}] = o
	}
	for _, c := range r.Cohorts {
		for _, o := range c.Outliers {
			fromOutliers[flaggedKey{o.Scope, o.Scanner, o.Field, o.Cluster}] = o
		}
	}
	if len(fromOutliers) == 0 {
		t.Fatal("fixture produced no outliers")
	}

	fromValues := map[flaggedKey]bool{}
	for _, d := range r.Distributions {
		if len(d.Values) != d.SampleSize {
			t.Errorf("%s %s/%s: %d values for a sample of %d", d.Scope, d.Scanner, d.Field, len(d.Values), d.SampleSize)
		}
		for _, v := range d.Values {
			if !v.Outlier {
				continue
			}
			k := flaggedKey{d.Scope, d.Scanner, d.Field, v.Cluster}
			fromValues[k] = true
			o, ok := fromOutliers[k]
			if !ok {
				t.Errorf("%+v flagged in the distribution but not by the detector", k)
				continue
			}
			if o.Median != d.Median || o.MAD != d.MAD || o.SampleSize != d.SampleSize || o.Threshold != d.Threshold {
				t.Errorf("%+v: outlier norm (%v, %v, n=%d, t=%v) differs from distribution (%v, %v, n=%d, t=%v)",
					k, o.Median, o.MAD, o.SampleSize, o.Threshold, d.Median, d.MAD, d.SampleSize, d.Threshold)
			}
			if o.Kind == NormKindNumeric && o.Z != v.Z {
				t.Errorf("%+v: outlier z %v, distribution z %v", k, o.Z, v.Z)
			}
		}
	}
	for k := range fromOutliers {
		if !fromValues[k] {
			t.Errorf("%+v flagged by the detector but not in its distribution", k)
		}
	}
}

// TestDistributionValues pins the fleet distributions of the untagged fixture
// to values computed by hand, then checks that tags measure a tagged cluster
// against its cohort.
func TestDistributionValues(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	r := Build(clusters, results, BuildOptions{})

	// enforced_count sorted: 20 22 23 24 24 24 25 26 26 28 30 80, median 24.5.
	// Absolute deviations: 4.5 2.5 1.5 0.5 0.5 0.5 0.5 1.5 1.5 3.5 5.5 55.5,
	// sorted 0.5 0.5 0.5 0.5 1.5 1.5 1.5 2.5 3.5 4.5 5.5 55.5, MAD (1.5+1.5)/2 = 1.5.
	// c05 at 80: z = 0.6745 * 55.5 / 1.5 = 24.9565. Band = 3.5 * 1.5 / 0.6745.
	enforced := findDistribution(t, r, NormScopeFleet, "security", "enforced_count")
	z := func(v float64) float64 { return madScale * (v - 24.5) / 1.5 }
	wantMass := 0.0
	for _, v := range []float64{20, 22, 24, 24, 24, 80, 26, 26, 28, 30, 25, 23} {
		wantMass += math.Min(math.Abs(z(v)), maxMassZ)
	}
	approx := cmpopts.EquateApprox(0, 1e-9)
	if diff := cmp.Diff([]float64{24.5, 1.5, 3.5 * 1.5 / madScale, 3.5, 12, wantMass},
		[]float64{enforced.Median, enforced.MAD, enforced.Band, enforced.Threshold, float64(enforced.SampleSize), enforced.Mass},
		approx); diff != "" {
		t.Errorf("enforced_count norm mismatch (-want +got):\n%s", diff)
	}
	var flagged []string
	for _, v := range enforced.Values {
		if v.Outlier {
			flagged = append(flagged, v.Cluster)
		}
		if diff := cmp.Diff(z(*v.Number), v.Z, approx); diff != "" {
			t.Errorf("%s z mismatch (-want +got):\n%s", v.Cluster, diff)
		}
	}
	if diff := cmp.Diff([]string{"c05"}, flagged); diff != "" {
		t.Errorf("enforced_count flagged mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(z(80), 24.9565, cmpopts.EquateApprox(0, 1e-4)); diff != "" {
		t.Errorf("c05 z mismatch (-want +got):\n%s", diff)
	}

	// quota_count is 6 everywhere but c03, so MAD is zero and the norm is exact: 11 of 12
	// hold the median, c03 is flagged with no z, and its mass is the full maxMassZ.
	quota := findDistribution(t, r, NormScopeFleet, "resource-quotas", "quota_count")
	if !quota.Exact || quota.MAD != 0 || quota.Band != 0 || quota.Mass != maxMassZ || quota.Median != 6 ||
		math.Abs(quota.ModeShare-11.0/12) > 1e-12 {
		t.Errorf("quota_count: want an exact norm at 6 held by 11/12, mass %v; got %+v", maxMassZ, quota)
	}
	for _, v := range quota.Values {
		if v.Outlier != (v.Cluster == "c03") || v.Z != 0 {
			t.Errorf("quota_count %s: want only c03 flagged, all with zero z, got %+v", v.Cluster, v)
		}
	}

	version := findDistribution(t, r, NormScopeFleet, "version", "git_version")
	if version.Mode != "v1.31.2" || math.Abs(version.ModeShare-11.0/12) > 1e-12 {
		t.Errorf("git_version: want mode v1.31.2 at 11/12, got %q at %v", version.Mode, version.ModeShare)
	}

	set := findDistribution(t, r, NormScopeFleet, "crds", "crd_names")
	wantConsensus := []string{"certificates.cert-manager.io", "issuers.cert-manager.io"}
	if diff := cmp.Diff(wantConsensus, set.Consensus); diff != "" {
		t.Errorf("crd_names consensus mismatch (-want +got):\n%s", diff)
	}
	for _, v := range set.Values {
		wantMissing := []string(nil)
		wantSize := 2
		if v.Cluster == "c09" {
			wantMissing = []string{"issuers.cert-manager.io"}
			wantSize = 1
		}
		if diff := cmp.Diff(wantMissing, v.Missing); diff != "" || v.Size != wantSize || v.Outlier != (wantMissing != nil) {
			t.Errorf("crd_names %s: want size %d missing %v, got %+v", v.Cluster, wantSize, wantMissing, v)
		}
	}

	if got := r.DeviationMass["c05"]; math.Abs(got-maxMassZ) > 1e-9 {
		t.Errorf("c05 deviation mass: want the cap %v from enforced_count alone, got %v", maxMassZ, got)
	}
	if got := r.DeviationMass["c00"]; math.Abs(got-math.Abs(z(20))) > 1e-9 {
		t.Errorf("c00 deviation mass: want %v, got %v", math.Abs(z(20)), got)
	}

	// Tagged, c03's quota of 9 against its east cohort's 6 counts in full, though the fleet,
	// with no spread on the field, gives it no z.
	tagged := Build(clusters, results, BuildOptions{ClusterTags: tags})
	if got := tagged.DeviationMass["c03"]; got < maxMassZ {
		t.Errorf("tagged c03 deviation mass: want at least %v from its cohort's quota norm, got %v", maxMassZ, got)
	}
}

// TestCohortDistributions verifies each cohort of six gets limited-sample
// distributions under its own scope, and that fleet scope comes first.
func TestCohortDistributions(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	r := Build(clusters, results, BuildOptions{ClusterTags: tags})

	scopes := map[string]int{}
	for _, d := range r.Distributions {
		scopes[d.Scope]++
		if d.Scope != NormScopeFleet && (!d.LimitedSample || d.SampleSize != 6) {
			t.Errorf("%s %s/%s: want a limited sample of 6, got limited=%v n=%d", d.Scope, d.Scanner, d.Field,
				d.LimitedSample, d.SampleSize)
		}
	}
	for _, s := range []string{NormScopeFleet, "east", "west"} {
		if scopes[s] == 0 {
			t.Errorf("no distributions with scope %q", s)
		}
	}
	if r.Distributions[0].Scope != NormScopeFleet {
		t.Errorf("first distribution has scope %q, want fleet", r.Distributions[0].Scope)
	}

	// Within east the values are 20 22 24 24 24 80: median 24, absolute
	// deviations 4 2 0 0 0 56, MAD (0+2)/2 = 1. The other five do not agree
	// within their own MAD of zero, so the majority diff flags nobody, and
	// c05 keeps its whole-population z of 0.6745 * 56 / 1 = 37.772.
	east := findDistribution(t, r, "east", "security", "enforced_count")
	if east.Median != 24 || east.MAD != 1 {
		t.Errorf("east enforced_count: want median 24 and MAD 1, got %v and %v", east.Median, east.MAD)
	}
	for _, v := range east.Values {
		if v.Outlier {
			t.Errorf("east %s flagged, want nothing flagged", v.Cluster)
		}
		if v.Cluster == "c05" && math.Abs(v.Z-37.772) > 1e-9 {
			t.Errorf("east c05: want z 37.772, got %v", v.Z)
		}
	}
}

// TestDistributionsSorted verifies distributions are ordered fleet first, then
// cohort name, then descending mass.
func TestDistributionsSorted(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	r := Build(clusters, results, BuildOptions{ClusterTags: tags})
	sorted := sort.SliceIsSorted(r.Distributions, func(i, j int) bool {
		a, b := r.Distributions[i], r.Distributions[j]
		if (a.Scope == NormScopeFleet) != (b.Scope == NormScopeFleet) {
			return a.Scope == NormScopeFleet
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Mass > b.Mass
	})
	if !sorted {
		t.Error("distributions are not sorted by scope then mass")
	}
}

// TestReportJSONSizeAtScale builds the benchmark fleet of 200 clusters widened
// to 24 scanners and checks the report JSON stays under 5 MB, the size at
// which distributions would need to move to their own endpoint.
func TestReportJSONSizeAtScale(t *testing.T) {
	t.Parallel()
	clusters, results := largeSyntheticFleet(200)
	for i, c := range clusters {
		for s := range 19 {
			name := fmt.Sprintf("scanner-%02d", s)
			data := map[string]any{}
			for f := range 6 {
				data[fmt.Sprintf("field_%d", f)] = float64((i*(s+3)+f*7)%50 + f)
			}
			results[c][name] = scanner.Result{Scanner: name, Data: data}
		}
	}
	r := Build(clusters, results)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dists, err := json.Marshal(r.Distributions)
	if err != nil {
		t.Fatalf("marshal distributions: %v", err)
	}
	t.Logf("report: %d bytes, distributions: %d bytes in %d", len(b), len(dists), len(r.Distributions))
	if len(b) > 5<<20 {
		t.Errorf("report is %d bytes, over 5 MB", len(b))
	}
}

// TestCohortMapFor verifies the report's cohort map places every cluster,
// labels each with its report cohort, and keeps the two tagged cohorts in
// contiguous runs of the leaf order.
func TestCohortMapFor(t *testing.T) {
	t.Parallel()
	clusters, results, tags := distributionFleet()
	r := Build(clusters, results, BuildOptions{ClusterTags: tags})
	m := CohortMapFor(r)
	if len(m.Points) != len(clusters) || len(m.LeafOrder) != len(clusters) {
		t.Fatalf("map has %d points and %d leaves, want %d", len(m.Points), len(m.LeafOrder), len(clusters))
	}
	for _, p := range m.Points {
		if p.Cohort != tags[p.Cluster] {
			t.Errorf("%s on the map in cohort %q, tagged %q", p.Cluster, p.Cohort, tags[p.Cluster])
		}
		if len(p.Peers) != cohortMapPeers {
			t.Errorf("%s has %d peers, want %d", p.Cluster, len(p.Peers), cohortMapPeers)
		}
	}
	runs := 0
	for i, c := range m.LeafOrder {
		if i == 0 || tags[m.LeafOrder[i-1]] != tags[c] {
			runs++
		}
	}
	if runs != 2 {
		t.Errorf("leaf order %v has %d cohort runs, want 2", m.LeafOrder, runs)
	}
	if got := CohortMapFor(nil); len(got.Points) != 0 {
		t.Errorf("nil report: want an empty map, got %d points", len(got.Points))
	}
}
