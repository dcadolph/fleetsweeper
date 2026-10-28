package cohort

import (
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// points returns profiles named p0, p1, ... at the given 2D positions.
func points(xy ...[2]float64) []ClusterProfile {
	out := make([]ClusterProfile, len(xy))
	for i, p := range xy {
		out[i] = ClusterProfile{Name: fmt.Sprintf("p%d", i), Features: []float64{p[0], p[1]}}
	}
	return out
}

// TestClassicalMDSRecoversDistances verifies that planar inputs come back with
// every pairwise distance intact and zero stress.
func TestClassicalMDSRecoversDistances(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Profiles []ClusterProfile
	}{{ // Test 0: Four points on a unit square, where the two eigenvalues tie.
		Profiles: points([2]float64{0, 0}, [2]float64{1, 0}, [2]float64{1, 1}, [2]float64{0, 1}),
	}, { // Test 1: Collinear points need only one axis.
		Profiles: points([2]float64{0, 0}, [2]float64{1, 1}, [2]float64{3, 3}, [2]float64{7, 7}),
	}, { // Test 2: An irregular planar layout.
		Profiles: points([2]float64{0.1, 0.9}, [2]float64{0.4, 0.2}, [2]float64{0.8, 0.7},
			[2]float64{0.3, 0.5}, [2]float64{0.9, 0.1}),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m := BuildMap(test.Profiles, nil, 0)
			for i := range test.Profiles {
				for j := i + 1; j < len(test.Profiles); j++ {
					want := euclidean(test.Profiles[i].Features, test.Profiles[j].Features)
					got := math.Hypot(m.Points[i].X-m.Points[j].X, m.Points[i].Y-m.Points[j].Y)
					if math.Abs(want-got) > 1e-6 {
						t.Errorf("distance %d-%d: want %v, got %v", i, j, want, got)
					}
				}
			}
			if m.Stress > 1e-6 {
				t.Errorf("stress: want 0, got %v", m.Stress)
			}
		})
	}
}

// TestMapStressNonPlanar verifies a layout that cannot be flattened reports
// nonzero stress: the four corners of a regular tetrahedron.
func TestMapStressNonPlanar(t *testing.T) {
	t.Parallel()
	profiles := []ClusterProfile{
		{Name: "a", Features: []float64{1, 1, 1}},
		{Name: "b", Features: []float64{1, -1, -1}},
		{Name: "c", Features: []float64{-1, 1, -1}},
		{Name: "d", Features: []float64{-1, -1, 1}},
	}
	if m := BuildMap(profiles, nil, 0); m.Stress < 0.05 {
		t.Errorf("stress: want a visible misfit, got %v", m.Stress)
	}
}

// TestMapLeafOrderKeepsCohortsContiguous tags clusters into two cohorts whose
// members interleave in feature space, so the raw dendrogram leaf order mixes
// them, and checks each cohort still forms one contiguous run.
func TestMapLeafOrderKeepsCohortsContiguous(t *testing.T) {
	t.Parallel()
	profiles := make([]ClusterProfile, 0, 8)
	for i := range 8 {
		tag := "east"
		if i%2 == 1 {
			tag = "west"
		}
		profiles = append(profiles, ClusterProfile{
			Name: fmt.Sprintf("c%d", i), Features: []float64{float64(i) / 8, float64(i%3) / 3}, Tag: tag,
		})
	}
	cohorts := Assign(profiles, Options{})
	m := BuildMap(profiles, cohorts, 3)

	cohortOf := map[string]string{}
	for _, p := range m.Points {
		cohortOf[p.Cluster] = p.Cohort
	}
	if len(m.LeafOrder) != len(profiles) {
		t.Fatalf("leaf order has %d clusters, want %d", len(m.LeafOrder), len(profiles))
	}
	runs := map[string]int{}
	for i, c := range m.LeafOrder {
		if i == 0 || cohortOf[m.LeafOrder[i-1]] != cohortOf[c] {
			runs[cohortOf[c]]++
		}
	}
	if diff := cmp.Diff(map[string]int{"east": 1, "west": 1}, runs); diff != "" {
		t.Errorf("runs per cohort mismatch (-want +got):\n%s\nleaf order: %v", diff, m.LeafOrder)
	}

	raw := leafOrder(buildDendrogram(len(profiles), pairwiseDistances(profiles)), len(profiles))
	switches := 0
	for i := 1; i < len(raw); i++ {
		if profiles[raw[i]].Tag != profiles[raw[i-1]].Tag {
			switches++
		}
	}
	if switches < 2 {
		t.Errorf("fixture does not interleave the cohorts in the raw leaf order (%d switches)", switches)
	}
}

// TestMapPeers verifies peers are the nearest clusters, closest first, ties by
// name, capped at the requested count.
func TestMapPeers(t *testing.T) {
	t.Parallel()
	profiles := points([2]float64{0, 0}, [2]float64{1, 0}, [2]float64{0, 1}, [2]float64{3, 0}, [2]float64{0, 5})
	m := BuildMap(profiles, nil, 3)
	want := []Peer{{Cluster: "p1", Distance: 1}, {Cluster: "p2", Distance: 1}, {Cluster: "p3", Distance: 3}}
	if diff := cmp.Diff(want, m.Points[0].Peers); diff != "" {
		t.Errorf("p0 peers mismatch (-want +got):\n%s", diff)
	}
	if got := BuildMap(profiles, nil, 0).Points[0].Peers; got != nil {
		t.Errorf("zero peers requested, got %v", got)
	}
}

// TestMapDeterministic verifies tied distances and identical profiles give the
// same map on every call.
func TestMapDeterministic(t *testing.T) {
	t.Parallel()
	profiles := make([]ClusterProfile, 0, 12)
	for i := range 12 {
		profiles = append(profiles, ClusterProfile{Name: fmt.Sprintf("c%02d", i), Features: []float64{float64(i % 2), 0}})
	}
	first := BuildMap(profiles, Assign(profiles, Options{}), 4)
	for range 30 {
		if diff := cmp.Diff(first, BuildMap(profiles, Assign(profiles, Options{}), 4)); diff != "" {
			t.Fatalf("map changed between calls (-first +again):\n%s", diff)
		}
	}
}

// TestMapEmpty verifies an empty fleet yields an empty map.
func TestMapEmpty(t *testing.T) {
	t.Parallel()
	if diff := cmp.Diff(Map{}, BuildMap(nil, nil, 5)); diff != "" {
		t.Errorf("empty map mismatch (-want +got):\n%s", diff)
	}
}
