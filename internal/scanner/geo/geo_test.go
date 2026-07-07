package geo

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// labeledNode builds a Node carrying the supplied topology labels.
func labeledNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// configMap builds the kube-system/fleetsweeper ConfigMap with the given data.
func configMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: configMapName, Namespace: configMapNamespace},
		Data:       data,
	}
}

// annotatedNamespace builds the kube-system namespace with the given annotations.
func annotatedNamespace(anns map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: configMapNamespace, Annotations: anns},
	}
}

// coordOpts compares coordinates and Data with float tolerance and treats nil
// and empty slices as equal.
var coordOpts = cmp.Options{cmpopts.EquateApprox(0, 1e-9), cmpopts.EquateEmpty()}

// TestParseFloat checks decimal parsing of ConfigMap and annotation strings,
// including trimming, empty input, and non-numeric input.
func TestParseFloat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In      string
		WantVal float64
		WantOK  bool
	}{{ // Test 0: Plain decimal parses.
		In: "12.5", WantVal: 12.5, WantOK: true,
	}, { // Test 1: Surrounding whitespace is trimmed.
		In: "  -3.5  ", WantVal: -3.5, WantOK: true,
	}, { // Test 2: Empty string fails.
		In: "", WantVal: 0, WantOK: false,
	}, { // Test 3: Whitespace only fails.
		In: "   ", WantVal: 0, WantOK: false,
	}, { // Test 4: Non-numeric input fails.
		In: "north", WantVal: 0, WantOK: false,
	}, { // Test 5: Scientific notation parses.
		In: "1e2", WantVal: 100, WantOK: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			gotVal, gotOK := parseFloat(test.In)
			if diff := cmp.Diff(test.WantOK, gotOK); diff != "" {
				t.Errorf("ok mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantVal, gotVal, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestValidCoord checks the Earth coordinate bounds at and beyond the limits.
func TestValidCoord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Lat       float64
		Lng       float64
		WantValid bool
	}{{ // Test 0: Null island is valid.
		Lat: 0, Lng: 0, WantValid: true,
	}, { // Test 1: Positive extremes are valid.
		Lat: 90, Lng: 180, WantValid: true,
	}, { // Test 2: Negative extremes are valid.
		Lat: -90, Lng: -180, WantValid: true,
	}, { // Test 3: Latitude above 90 is invalid.
		Lat: 90.1, Lng: 0, WantValid: false,
	}, { // Test 4: Latitude below -90 is invalid.
		Lat: -90.1, Lng: 0, WantValid: false,
	}, { // Test 5: Longitude above 180 is invalid.
		Lat: 0, Lng: 180.1, WantValid: false,
	}, { // Test 6: Longitude below -180 is invalid.
		Lat: 0, Lng: -180.1, WantValid: false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := validCoord(test.Lat, test.Lng)
			if diff := cmp.Diff(test.WantValid, got); diff != "" {
				t.Errorf("valid mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFirstLabel checks priority ordering and empty-value handling for the
// region label lookup.
func TestFirstLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Labels    map[string]string
		Keys      []string
		WantValue string
	}{{ // Test 0: Stable region label is returned.
		Labels: map[string]string{"topology.kubernetes.io/region": "us-east-1"},
		Keys:   regionLabels, WantValue: "us-east-1",
	}, { // Test 1: Legacy label used when stable is absent.
		Labels: map[string]string{"failure-domain.beta.kubernetes.io/region": "eu-west-1"},
		Keys:   regionLabels, WantValue: "eu-west-1",
	}, { // Test 2: Stable label takes priority over legacy.
		Labels: map[string]string{
			"topology.kubernetes.io/region":            "us-east-1",
			"failure-domain.beta.kubernetes.io/region": "eu-west-1",
		},
		Keys: regionLabels, WantValue: "us-east-1",
	}, { // Test 3: Empty value is treated as absent.
		Labels: map[string]string{"topology.kubernetes.io/region": ""},
		Keys:   regionLabels, WantValue: "",
	}, { // Test 4: No matching key returns empty.
		Labels: map[string]string{"kubernetes.io/hostname": "node-a"},
		Keys:   regionLabels, WantValue: "",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := firstLabel(test.Labels, test.Keys)
			if diff := cmp.Diff(test.WantValue, got); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDominantRegion checks winner selection by count with alphabetical tie
// breaking and the empty-map case.
func TestDominantRegion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Counts     map[string]int
		WantRegion string
	}{{ // Test 0: Clear winner by count.
		Counts: map[string]int{"us-east-1": 3, "us-west-2": 1}, WantRegion: "us-east-1",
	}, { // Test 1: Tie broken alphabetically.
		Counts: map[string]int{"eu-west-1": 2, "ap-south-1": 2}, WantRegion: "ap-south-1",
	}, { // Test 2: Single region wins.
		Counts: map[string]int{"solo": 5}, WantRegion: "solo",
	}, { // Test 3: Empty map yields empty string.
		Counts: map[string]int{}, WantRegion: "",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := dominantRegion(test.Counts)
			if diff := cmp.Diff(test.WantRegion, got); diff != "" {
				t.Errorf("region mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDerivedRegionFromZone checks trimming of AWS and GCP zone suffixes and
// the pass-through of values that do not carry a recognizable suffix.
func TestDerivedRegionFromZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Zone       string
		WantRegion string
	}{{ // Test 0: AWS zone drops the trailing letter.
		Zone: "us-east-1a", WantRegion: "us-east-1",
	}, { // Test 1: GCP zone drops the trailing letter and hyphen.
		Zone: "us-central1-b", WantRegion: "us-central1",
	}, { // Test 2: Suffix outside a-f is left intact.
		Zone: "us-east-1z", WantRegion: "us-east-1z",
	}, { // Test 3: Value without a zone suffix is unchanged.
		Zone: "us-east-1", WantRegion: "us-east-1",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := derivedRegionFromZone(test.Zone, Coord{})
			if diff := cmp.Diff(test.WantRegion, got); diff != "" {
				t.Errorf("region mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSortedKeys checks that map keys are returned as a sorted slice.
func TestSortedKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In       map[string]int
		WantKeys []string
	}{{ // Test 0: Keys returned in sorted order.
		In: map[string]int{"c": 1, "a": 2, "b": 3}, WantKeys: []string{"a", "b", "c"},
	}, { // Test 1: Empty map yields empty slice.
		In: map[string]int{}, WantKeys: []string{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := sortedKeys(test.In)
			if diff := cmp.Diff(test.WantKeys, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("keys mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCollectRegionsZones checks that region counts and the zone set are
// accumulated from node labels, ignoring nodes without labels.
func TestCollectRegionsZones(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Nodes           []*corev1.Node
		WantRegionCount map[string]int
		WantZones       []string
	}{{ // Test 0: Region and zone both recorded.
		Nodes: []*corev1.Node{labeledNode("n1", map[string]string{
			"topology.kubernetes.io/region": "us-east-1",
			"topology.kubernetes.io/zone":   "us-east-1a",
		})},
		WantRegionCount: map[string]int{"us-east-1": 1},
		WantZones:       []string{"us-east-1a"},
	}, { // Test 1: Zone-only node adds no region count.
		Nodes: []*corev1.Node{labeledNode("n1", map[string]string{
			"topology.kubernetes.io/zone": "us-west-2b",
		})},
		WantRegionCount: map[string]int{},
		WantZones:       []string{"us-west-2b"},
	}, { // Test 2: Node without labels contributes nothing.
		Nodes:           []*corev1.Node{labeledNode("n1", nil)},
		WantRegionCount: map[string]int{},
		WantZones:       []string{},
	}, { // Test 3: Two nodes in one region accumulate distinct zones.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{
				"topology.kubernetes.io/region": "us-east-1",
				"topology.kubernetes.io/zone":   "us-east-1a",
			}),
			labeledNode("n2", map[string]string{
				"topology.kubernetes.io/region": "us-east-1",
				"topology.kubernetes.io/zone":   "us-east-1b",
			}),
		},
		WantRegionCount: map[string]int{"us-east-1": 2},
		WantZones:       []string{"us-east-1a", "us-east-1b"},
	}, { // Test 4: Legacy failure-domain labels are honored.
		Nodes: []*corev1.Node{labeledNode("n1", map[string]string{
			"failure-domain.beta.kubernetes.io/region": "eu-west-1",
			"failure-domain.beta.kubernetes.io/zone":   "eu-west-1a",
		})},
		WantRegionCount: map[string]int{"eu-west-1": 1},
		WantZones:       []string{"eu-west-1a"},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			items := make([]corev1.Node, len(test.Nodes))
			for i, n := range test.Nodes {
				items[i] = *n
			}
			regionCount := map[string]int{}
			zoneSet := map[string]struct{}{}
			collectRegionsZones(items, regionCount, zoneSet)
			if diff := cmp.Diff(test.WantRegionCount, regionCount, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("region count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantZones, sortedKeys(zoneSet), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("zones mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLookup checks direct region-table lookups for hits and misses.
func TestLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Region    string
		WantCoord Coord
		WantOK    bool
	}{{ // Test 0: Known AWS region resolves.
		Region:    "us-east-1",
		WantCoord: Coord{Lat: 38.95, Lng: -77.46, Provider: "AWS", City: "N. Virginia"},
		WantOK:    true,
	}, { // Test 1: Known GCP region resolves.
		Region:    "us-central1",
		WantCoord: Coord{Lat: 41.26, Lng: -95.93, Provider: "GCP", City: "Iowa"},
		WantOK:    true,
	}, { // Test 2: Unknown region misses.
		Region: "atlantis-1", WantCoord: Coord{}, WantOK: false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, ok := Lookup(test.Region)
			if diff := cmp.Diff(test.WantOK, ok); diff != "" {
				t.Errorf("ok mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCoord, got, coordOpts); diff != "" {
				t.Errorf("coord mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLookupZone checks zone-suffix trimming for AWS and GCP shapes plus the
// exact-region and not-found cases.
func TestLookupZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Zone      string
		WantCoord Coord
		WantOK    bool
	}{{ // Test 0: AWS zone trims to its region.
		Zone:      "us-east-1a",
		WantCoord: Coord{Lat: 38.95, Lng: -77.46, Provider: "AWS", City: "N. Virginia"},
		WantOK:    true,
	}, { // Test 1: GCP zone trims trailing letter and hyphen.
		Zone:      "us-central1-b",
		WantCoord: Coord{Lat: 41.26, Lng: -95.93, Provider: "GCP", City: "Iowa"},
		WantOK:    true,
	}, { // Test 2: Exact region string resolves without trimming.
		Zone:      "eu-west-1",
		WantCoord: Coord{Lat: 53.33, Lng: -6.25, Provider: "AWS", City: "Ireland"},
		WantOK:    true,
	}, { // Test 3: Single character cannot be a zone.
		Zone: "a", WantCoord: Coord{}, WantOK: false,
	}, { // Test 4: Unknown zone misses.
		Zone: "zz-nowhere-9x", WantCoord: Coord{}, WantOK: false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, ok := LookupZone(test.Zone)
			if diff := cmp.Diff(test.WantOK, ok); diff != "" {
				t.Errorf("ok mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCoord, got, coordOpts); diff != "" {
				t.Errorf("coord mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestScan drives the full geo scanner over the typed fake, covering
// auto-detect from region and zone labels, ConfigMap and namespace-annotation
// overrides, the no-location case, and a node list error.
func TestScan(t *testing.T) {
	t.Parallel()

	stableRegion := map[string]string{
		"topology.kubernetes.io/region": "us-east-1",
		"topology.kubernetes.io/zone":   "us-east-1a",
	}

	tests := []struct {
		Nodes     []*corev1.Node
		ConfigMap *corev1.ConfigMap
		Namespace *corev1.Namespace
		ListErr   bool
		WantData  Data
	}{{ // Test 0: Auto-detect picks the dominant region.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "us-east-1"}),
			labeledNode("n2", map[string]string{"topology.kubernetes.io/region": "us-east-1"}),
			labeledNode("n3", map[string]string{"topology.kubernetes.io/region": "us-west-2"}),
		},
		WantData: Data{
			Region: "us-east-1", Provider: "AWS", City: "N. Virginia",
			Lat: 38.95, Lng: -77.46, HasLocation: true, Source: "auto",
			Regions: []string{"us-east-1", "us-west-2"}, NodeCount: 3, LocatedNodes: 2,
		},
	}, { // Test 1: Zone-only node derives its region.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{"topology.kubernetes.io/zone": "us-east-1a"}),
		},
		WantData: Data{
			Region: "us-east-1", Provider: "AWS", City: "N. Virginia",
			Lat: 38.95, Lng: -77.46, HasLocation: true, Source: "auto",
			Regions: []string{"us-east-1"}, Zones: []string{"us-east-1a"},
			NodeCount: 1, LocatedNodes: 1,
		},
	}, { // Test 2: ConfigMap override wins over auto-detect.
		Nodes:     []*corev1.Node{labeledNode("n1", stableRegion)},
		ConfigMap: configMap(map[string]string{"lat": "12.34", "lng": "56.78", "site": "dc-1", "notes": "primary"}),
		WantData: Data{
			Lat: 12.34, Lng: 56.78, HasLocation: true, Source: "configmap",
			Site: "dc-1", Notes: "primary", City: "dc-1",
			Regions: []string{"us-east-1"}, Zones: []string{"us-east-1a"}, NodeCount: 1,
		},
	}, { // Test 3: Namespace annotations override auto-detect.
		Nodes: []*corev1.Node{labeledNode("n1", stableRegion)},
		Namespace: annotatedNamespace(map[string]string{
			annoLat: "12.34", annoLng: "56.78", annoSite: "site-x", annoNotes: "note-y",
		}),
		WantData: Data{
			Lat: 12.34, Lng: 56.78, HasLocation: true, Source: "annotation",
			Site: "site-x", Notes: "note-y", City: "site-x",
			Regions: []string{"us-east-1"}, Zones: []string{"us-east-1a"}, NodeCount: 1,
		},
	}, { // Test 4: Nodes without topology labels resolve no location.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{"kubernetes.io/hostname": "n1"}),
			labeledNode("n2", nil),
		},
		WantData: Data{NodeCount: 2},
	}, { // Test 5: A node list error yields empty data.
		Nodes:    []*corev1.Node{labeledNode("n1", stableRegion)},
		ListErr:  true,
		WantData: Data{},
	}, { // Test 6: A region label holding a zone value resolves via zone fallback.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "us-east-1a"}),
		},
		WantData: Data{
			Region: "us-east-1a", Provider: "AWS", City: "N. Virginia",
			Lat: 38.95, Lng: -77.46, HasLocation: true, Source: "auto",
			Regions: []string{"us-east-1a"}, NodeCount: 1, LocatedNodes: 1,
		},
	}, { // Test 7: ConfigMap region key fills provider and city from the table.
		Nodes:     []*corev1.Node{labeledNode("n1", stableRegion)},
		ConfigMap: configMap(map[string]string{"lat": "1.0", "lng": "2.0", "region": "eu-central-1"}),
		WantData: Data{
			Lat: 1.0, Lng: 2.0, HasLocation: true, Source: "configmap",
			Region: "eu-central-1", Provider: "AWS", City: "Frankfurt",
			Regions: []string{"us-east-1"}, Zones: []string{"us-east-1a"}, NodeCount: 1,
		},
	}, { // Test 8: ConfigMap without coordinates falls through to auto-detect.
		Nodes:     []*corev1.Node{labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "us-west-2"})},
		ConfigMap: configMap(map[string]string{"site": "x"}),
		WantData: Data{
			Region: "us-west-2", Provider: "AWS", City: "Oregon",
			Lat: 45.51, Lng: -122.68, HasLocation: true, Source: "auto",
			Regions: []string{"us-west-2"}, NodeCount: 1, LocatedNodes: 1,
		},
	}, { // Test 9: ConfigMap with out-of-bounds coordinates falls through.
		Nodes:     []*corev1.Node{labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "us-west-1"})},
		ConfigMap: configMap(map[string]string{"lat": "999", "lng": "0"}),
		WantData: Data{
			Region: "us-west-1", Provider: "AWS", City: "N. California",
			Lat: 37.77, Lng: -122.42, HasLocation: true, Source: "auto",
			Regions: []string{"us-west-1"}, NodeCount: 1, LocatedNodes: 1,
		},
	}, { // Test 10: Namespace annotations without coordinates fall through.
		Nodes:     []*corev1.Node{labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "ap-south-1"})},
		Namespace: annotatedNamespace(map[string]string{annoSite: "x"}),
		WantData: Data{
			Region: "ap-south-1", Provider: "AWS", City: "Mumbai",
			Lat: 19.08, Lng: 72.88, HasLocation: true, Source: "auto",
			Regions: []string{"ap-south-1"}, NodeCount: 1, LocatedNodes: 1,
		},
	}, { // Test 11: An unknown zone is recorded but resolves no region.
		Nodes: []*corev1.Node{
			labeledNode("n1", map[string]string{"topology.kubernetes.io/zone": "weird-zone-x"}),
		},
		WantData: Data{Zones: []string{"weird-zone-x"}, NodeCount: 1},
	}, { // Test 12: Namespace annotations with out-of-bounds coordinates fall through.
		Nodes:     []*corev1.Node{labeledNode("n1", map[string]string{"topology.kubernetes.io/region": "eu-west-2"})},
		Namespace: annotatedNamespace(map[string]string{annoLat: "999", annoLng: "0"}),
		WantData: Data{
			Region: "eu-west-2", Provider: "AWS", City: "London",
			Lat: 51.50, Lng: -0.13, HasLocation: true, Source: "auto",
			Regions: []string{"eu-west-2"}, NodeCount: 1, LocatedNodes: 1,
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var objects []runtime.Object
			for _, n := range test.Nodes {
				objects = append(objects, n)
			}
			if test.ConfigMap != nil {
				objects = append(objects, test.ConfigMap)
			}
			if test.Namespace != nil {
				objects = append(objects, test.Namespace)
			}
			cs := fakeclientset.NewSimpleClientset(objects...)
			if test.ListErr {
				cs.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("boom")
				})
			}
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(Name, result.Scanner); diff != "" {
				t.Errorf("scanner name mismatch (-want +got):\n%s", diff)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			if diff := cmp.Diff(test.WantData, data, coordOpts); diff != "" {
				t.Errorf("data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
