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
