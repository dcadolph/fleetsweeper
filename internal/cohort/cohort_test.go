package cohort

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestAssign(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name     string
		Profiles []ClusterProfile
		Opts     Options
		WantLen  int
		WantTags map[string]bool // tagged clusters that must appear under their tag
	}{
		{ // Test 0: empty input produces no cohorts.
			Name:    "empty",
			WantLen: 0,
		},
		{ // Test 1: a tiny fleet becomes a single "fleet" cohort.
			Name: "below_min_clusters",
			Profiles: []ClusterProfile{
				{Name: "a", Features: []float64{0.1}},
				{Name: "b", Features: []float64{0.2}},
				{Name: "c", Features: []float64{0.3}},
			},
			WantLen: 1,
		},
		{ // Test 2: tags win regardless of feature similarity.
			Name: "tags_win",
			Profiles: []ClusterProfile{
				{Name: "a", Features: []float64{0.0}, Tag: "prod"},
				{Name: "b", Features: []float64{0.9}, Tag: "prod"},
				{Name: "c", Features: []float64{0.1}, Tag: "dev"},
				{Name: "d", Features: []float64{0.95}, Tag: "dev"},
			},
			WantLen: 2,
			WantTags: map[string]bool{
				"prod": true,
				"dev":  true,
			},
		},
		{ // Test 3: clearly separated populations get their own auto cohorts.
			Name: "two_clean_clusters",
			Profiles: []ClusterProfile{
				{Name: "a1", Features: []float64{0.1, 0.1}},
				{Name: "a2", Features: []float64{0.12, 0.08}},
				{Name: "a3", Features: []float64{0.09, 0.11}},
				{Name: "a4", Features: []float64{0.11, 0.13}},
				{Name: "b1", Features: []float64{0.9, 0.9}},
				{Name: "b2", Features: []float64{0.88, 0.92}},
				{Name: "b3", Features: []float64{0.93, 0.87}},
				{Name: "b4", Features: []float64{0.91, 0.89}},
			},
			WantLen: 2,
		},
		{ // Test 4: tagged and untagged coexist; both kinds appear in output.
			Name: "mixed_tagged_and_auto",
			Profiles: []ClusterProfile{
				{Name: "e1", Features: []float64{0.0, 0.0}, Tag: "edge"},
				{Name: "e2", Features: []float64{0.05, 0.05}, Tag: "edge"},
				{Name: "p1", Features: []float64{0.5, 0.5}},
				{Name: "p2", Features: []float64{0.52, 0.48}},
				{Name: "p3", Features: []float64{0.49, 0.51}},
				{Name: "p4", Features: []float64{0.5, 0.52}},
				{Name: "d1", Features: []float64{0.95, 0.95}},
				{Name: "d2", Features: []float64{0.92, 0.97}},
				{Name: "d3", Features: []float64{0.96, 0.93}},
				{Name: "d4", Features: []float64{0.97, 0.92}},
			},
			WantLen: 3, // edge (tagged) + 2 auto
			WantTags: map[string]bool{
				"edge": true,
			},
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := Assign(test.Profiles, test.Opts)
			if diff := cmp.Diff(test.WantLen, len(got), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("cohort count mismatch (-want +got):\n%s\ngot=%+v", diff, got)
			}
			for tag := range test.WantTags {
				if !cohortPresent(got, tag, SourceTagged) {
					t.Errorf("expected tagged cohort %q, got %+v", tag, got)
				}
			}
			for _, c := range got {
				if len(c.Clusters) == 0 {
					t.Errorf("empty cohort %q", c.Name)
				}
				if !isSorted(c.Clusters) {
					t.Errorf("cohort %q members not sorted: %v", c.Name, c.Clusters)
				}
			}
		})
	}
}

func TestAssignDeterministic(t *testing.T) {
	t.Parallel()
	profiles := []ClusterProfile{
		{Name: "a1", Features: []float64{0.1, 0.1}},
		{Name: "a2", Features: []float64{0.11, 0.09}},
		{Name: "a3", Features: []float64{0.09, 0.12}},
		{Name: "a4", Features: []float64{0.1, 0.1}},
		{Name: "b1", Features: []float64{0.9, 0.9}},
		{Name: "b2", Features: []float64{0.91, 0.89}},
		{Name: "b3", Features: []float64{0.89, 0.92}},
		{Name: "b4", Features: []float64{0.9, 0.9}},
	}
	first := Assign(profiles, Options{})
	second := Assign(profiles, Options{})
	if diff := cmp.Diff(first, second); diff != "" {
		t.Errorf("cohort assignment not deterministic (-first +second):\n%s", diff)
	}
}

func TestProfiles(t *testing.T) {
	t.Parallel()
	clusters := []string{"a", "b", "c"}
	lookup := stubLookup{
		"resources": {
			"a": map[string]any{"node_count": 6.0},
			"b": map[string]any{"node_count": 3.0},
			"c": map[string]any{"node_count": 9.0},
		},
		"namespaces": {
			"a": map[string]any{"count": 12.0},
			"b": map[string]any{"count": 8.0},
			"c": map[string]any{"count": 12.0},
		},
		"version": {
			"a": map[string]any{"minor": "31"},
			"b": map[string]any{"minor": "30"},
			"c": map[string]any{"minor": "31+"},
		},
	}
	tags := map[string]string{"a": "prod"}
	got := Profiles(clusters, lookup, tags)
	if len(got) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(got))
	}
	if got[0].Tag != "prod" {
		t.Errorf("expected tag prod on first profile, got %q", got[0].Tag)
	}
	for _, p := range got {
		for _, f := range p.Features {
			if f < 0 || f > 1 {
				t.Errorf("feature out of [0,1] for %s: %v", p.Name, p.Features)
				break
			}
		}
	}
}

func TestMinorVersionExtractor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In     any
		Want   float64
		WantOK bool
	}{
		{In: "31", Want: 31, WantOK: true},
		{In: "31+", Want: 31, WantOK: true},
		{In: 30.0, Want: 30, WantOK: true},
		{In: 29, Want: 29, WantOK: true},
		{In: "", WantOK: false},
		{In: "abc", WantOK: false},
		{In: nil, WantOK: false},
	}
	for testNum, test := range tests {
		got, ok := minorVersionExtractor(test.In)
		if ok != test.WantOK {
			t.Errorf("test %d: ok mismatch: want %v, got %v", testNum, test.WantOK, ok)
			continue
		}
		if ok && got != test.Want {
			t.Errorf("test %d: value mismatch: want %v, got %v", testNum, test.Want, got)
		}
	}
}

// stubLookup is a minimal SectionLookup implementation for tests.
type stubLookup map[string]map[string]any

// PerCluster returns the per-cluster map for a scanner.
func (s stubLookup) PerCluster(scanner string) map[string]any {
	return s[scanner]
}

// cohortPresent reports whether got contains a cohort with the given name and source.
func cohortPresent(got []Cohort, name string, source Source) bool {
	for _, c := range got {
		if c.Name == name && c.Source == source {
			return true
		}
	}
	return false
}

// isSorted reports whether s is sorted ascending.
func isSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

// oneHot returns a vector of length dims with 1 at index hot and off added at
// the last index, so group members sit a tiny, distinct distance apart.
func oneHot(dims, hot int, off float64) []float64 {
	v := make([]float64, dims)
	v[hot] = 1
	v[dims-1] += off
	return v
}

// nineGroups builds 27 profiles in nine groups of three. Groups g0 to g7 sit on
// unit axes 0 to 7, pairwise sqrt(2) apart. Group g8 sits at axis 7 plus axis 8,
// one unit from g7 and sqrt(3) from the rest, so g7 and g8 merge first.
func nineGroups() []ClusterProfile {
	const dims = 10
	offs := []float64{0, 0.001, 0.003}
	out := make([]ClusterProfile, 0, 9*len(offs))
	for g := range 9 {
		for m, off := range offs {
			hot := g
			if g == 8 {
				hot = 7
			}
			v := oneHot(dims, hot, off)
			if g == 8 {
				v[8] = 1
			}
			out = append(out, ClusterProfile{Name: fmt.Sprintf("g%d-%d", g, m), Features: v})
		}
	}
	return out
}

// groupNames returns the three member names of nine-group fleet group g.
func groupNames(gs ...int) []string {
	out := make([]string, 0, 3*len(gs))
	for _, g := range gs {
		for m := range 3 {
			out = append(out, fmt.Sprintf("g%d-%d", g, m))
		}
	}
	return out
}

// TestAssignGolden pins exact cohort membership at the size and count
// boundaries. Merge distances in each comment are average-linkage values
// computed by hand.
func TestAssignGolden(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	// Two groups of three on a line: a at 0, 0.01, 0.03 and b at 1, 1.02, 1.05.
	// Merges: a1a2 0.01, b1b2 0.02, a3 0.025, b3 0.04, a-b 1.01. The largest
	// gap precedes the last merge, so K is 2.
	sixLine := []ClusterProfile{
		{Name: "a1", Features: []float64{0}},
		{Name: "a2", Features: []float64{0.01}},
		{Name: "a3", Features: []float64{0.03}},
		{Name: "b1", Features: []float64{1}},
		{Name: "b2", Features: []float64{1.02}},
		{Name: "b3", Features: []float64{1.05}},
	}

	autoNine := make([]Cohort, 0, 9)
	for g := range 9 {
		autoNine = append(autoNine, Cohort{
			Name: fmt.Sprintf("auto-%d", g+1), Source: SourceAuto, Clusters: groupNames(g),
		})
	}
	autoEight := append([]Cohort(nil), autoNine[:7]...)
	autoEight = append(autoEight, Cohort{Name: "auto-8", Source: SourceAuto, Clusters: groupNames(7, 8)})

	tests := []struct {
		Name        string
		Profiles    []ClusterProfile
		Opts        Options
		WantCohorts []Cohort
	}{{ // Test 0: Five clusters are under the six-cluster floor, so one fleet cohort.
		Name:     "n=5 is one fleet cohort",
		Profiles: sixLine[1:],
		WantCohorts: []Cohort{
			{Name: "fleet", Source: SourceFleet, Clusters: []string{"a2", "a3", "b1", "b2", "b3"}},
		},
	}, { // Test 1: Six clusters reach the floor and split into the two groups.
		Name:     "n=6 splits",
		Profiles: sixLine,
		WantCohorts: []Cohort{
			{Name: "auto-1", Source: SourceAuto, Clusters: []string{"a1", "a2", "a3"}},
			{Name: "auto-2", Source: SourceAuto, Clusters: []string{"b1", "b2", "b3"}},
		},
	}, { // Test 2: A singleton s at (0.6,1.2) is cut out at K=3. Merges: a within
		// 0.01 and 0.021, b within 0.03 and 0.045, a-b about 1.01, s last at about
		// 1.3. The gap before a-b (0.965) beats the gap before s (0.29), so K=3 and
		// s stands alone. Its nearest member is b3 at 1.227 against a3 at 1.324,
		// so s folds into b.
		Name: "singleton folds into nearest cohort",
		Profiles: []ClusterProfile{
			{Name: "a1", Features: []float64{0, 0}},
			{Name: "a2", Features: []float64{0.01, 0}},
			{Name: "a3", Features: []float64{0, 0.02}},
			{Name: "b1", Features: []float64{1, 0}},
			{Name: "b2", Features: []float64{1.03, 0}},
			{Name: "b3", Features: []float64{1, 0.04}},
			{Name: "s", Features: []float64{0.6, 1.2}},
		},
		WantCohorts: []Cohort{
			{Name: "auto-1", Source: SourceAuto, Clusters: []string{"a1", "a2", "a3"}},
			{Name: "auto-2", Source: SourceAuto, Clusters: []string{"b1", "b2", "b3", "s"}},
		},
	}, { // Test 3: Nine groups want K=9 (gap 1.0 before the g7-g8 merge), the cap
		// of 8 forces the cut after it, so g7 and g8 share a cohort. The gap at K=8
		// is 1.414-1.0=0.414 and every later gap is under 0.16.
		Name:        "nine groups capped at eight",
		Profiles:    nineGroups(),
		WantCohorts: autoEight,
	}, { // Test 4: With the cap raised to nine, the same fleet keeps all nine groups.
		Name:        "nine groups with cap nine",
		Profiles:    nineGroups(),
		Opts:        Options{MaxCohorts: 9},
		WantCohorts: autoNine,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := Assign(test.Profiles, test.Opts)
			if diff := cmp.Diff(test.WantCohorts, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("cohorts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProfilesGolden pins exact imputed and normalized feature vectors. Feature
// order follows featureSpecs: node_count, namespace_count, service_count,
// ingress_count, cluster_role_count, crd_count, avg_cpu_percent,
// avg_memory_percent, enforced_count, network_policy_count, quota_count,
// minor_version.
func TestProfilesGolden(t *testing.T) {
	t.Parallel()

	// node_count 6, 3, 9 normalizes over span 6 to 0.5, 0, 1. namespace count
	// 12, 8, missing imputes the median 10, then normalizes over span 4 to 1, 0,
	// 0.5. services only on a (5) imputes 5 everywhere, a zero span, so 0. minor
	// 31, 30, 31+ normalizes to 1, 0, 1. Every other feature is absent and 0.
	lookup := stubLookup{
		"resources": {
			"a": map[string]any{"node_count": 6.0},
			"b": map[string]any{"node_count": 3.0},
			"c": map[string]any{"node_count": 9.0},
		},
		"namespaces": {
			"a": map[string]any{"count": 12.0},
			"b": map[string]any{"count": 8.0},
		},
		"services": {
			"a": map[string]any{"count": 5.0},
		},
		"version": {
			"a": map[string]any{"minor": "31"},
			"b": map[string]any{"minor": "30"},
			"c": map[string]any{"minor": "31+"},
		},
	}

	got := Profiles([]string{"a", "b", "c"}, lookup, map[string]string{"a": "prod"})
	want := []ClusterProfile{
		{Name: "a", Tag: "prod", Features: []float64{0.5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{Name: "b", Features: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{Name: "c", Features: []float64{1, 0.5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
		t.Errorf("profiles mismatch (-want +got):\n%s", diff)
	}
}
