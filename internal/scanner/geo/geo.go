// Package geo locates clusters on Earth from node region/zone labels.
//
// Kubernetes nodes carry well-known topology labels populated by every major
// cloud provider's controller-manager: topology.kubernetes.io/region and
// topology.kubernetes.io/zone. Older clusters used failure-domain.beta.* on
// the same data. By reading these on every node and consulting an embedded
// region-to-coordinate table, we can place a cluster on a globe with no
// manual configuration.
package geo

import (
	"context"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Annotation keys recognized on the kube-system namespace. Operators can
// stamp these via kubectl, Helm, kustomize, or Argo and the values flow
// through to the globe without touching fleetsweeper's database.
const (
	annoLat   = "fleetsweeper.io/lat"
	annoLng   = "fleetsweeper.io/lng"
	annoSite  = "fleetsweeper.io/site"
	annoNotes = "fleetsweeper.io/notes"
)

// configMapName is the conventional name for the in-cluster fleetsweeper
// configuration ConfigMap. Lives in kube-system so it survives namespace
// churn and matches the pattern set by kubeadm-config, coredns, and kube-proxy.
const configMapName = "fleetsweeper"

// configMapNamespace is where configMapName must live.
const configMapNamespace = "kube-system"

// Name is the registry key for this scanner.
const Name = "geo"

// regionLabels are the node labels we consult, in priority order. The
// stable labels (topology.kubernetes.io/...) supersede the legacy
// failure-domain.beta.kubernetes.io/... values when both are present.
var regionLabels = []string{
	"topology.kubernetes.io/region",
	"failure-domain.beta.kubernetes.io/region",
}

// zoneLabels mirror regionLabels for the zone dimension.
var zoneLabels = []string{
	"topology.kubernetes.io/zone",
	"failure-domain.beta.kubernetes.io/zone",
}

// Data is the geographic placement information for one cluster.
type Data struct {
	// Region is the inferred cloud region (for example "us-east-1").
	Region string `json:"region,omitempty"`
	// Provider is the inferred provider name (AWS, GCP, Azure, ...).
	Provider string `json:"provider,omitempty"`
	// City is a human-readable name for the region centroid.
	City string `json:"city,omitempty"`
	// Site is the operator-supplied site label (when an in-cluster
	// annotation or ConfigMap is present).
	Site string `json:"site,omitempty"`
	// Notes is operator-supplied free-form text.
	Notes string `json:"notes,omitempty"`
	// Lat is latitude in degrees. NaN when unknown; serialized as 0.
	Lat float64 `json:"lat"`
	// Lng is longitude in degrees. NaN when unknown; serialized as 0.
	Lng float64 `json:"lng"`
	// HasLocation is true when Lat/Lng were resolved.
	HasLocation bool `json:"has_location"`
	// Source describes where the location came from: "configmap",
	// "annotation", "auto", or "" when unresolved. The handler that merges
	// manual DB overrides treats "configmap" and "annotation" as
	// operator-asserted and surfaces them as "manual" on the globe.
	Source string `json:"source,omitempty"`
	// Regions lists every distinct region observed across nodes (a single
	// cluster usually has one, but federated clusters can span multiple).
	Regions []string `json:"regions,omitempty"`
	// Zones lists every distinct zone observed across nodes.
	Zones []string `json:"zones,omitempty"`
	// NodeCount is the number of nodes inspected.
	NodeCount int `json:"node_count"`
	// LocatedNodes is the number of nodes whose region was resolved.
	LocatedNodes int `json:"located_nodes"`
}

// NewScanner returns a scanner that reads node region/zone labels and
// resolves a single representative coordinate for the cluster.
//
// Resolution order, highest priority first:
//  1. ConfigMap kube-system/fleetsweeper with lat/lng/site keys.
//  2. Annotations on the kube-system namespace (fleetsweeper.io/lat etc.).
//  3. Auto-detect from node region labels.
//
// Whichever source wins is recorded in Data.Source so consumers can show
// the operator which configuration is currently active.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		nodes, err := client.Clientset().CoreV1().Nodes().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{Scanner: Name, Data: Data{}}, nil
		}

		regionCount := map[string]int{}
		zoneSet := map[string]struct{}{}
		data := Data{NodeCount: len(nodes.Items)}

		if applied := applyConfigMap(ctx, client, &data); applied {
			collectRegionsZones(nodes.Items, regionCount, zoneSet)
			data.Regions, data.Zones = sortedKeys(regionCount), sortedKeys(zoneSet)
			return scanner.Result{Scanner: Name, Data: data}, nil
		}
		if applied := applyNamespaceAnnotations(ctx, client, &data); applied {
			collectRegionsZones(nodes.Items, regionCount, zoneSet)
			data.Regions, data.Zones = sortedKeys(regionCount), sortedKeys(zoneSet)
			return scanner.Result{Scanner: Name, Data: data}, nil
		}

		for i := range nodes.Items {
			labels := nodes.Items[i].Labels
			if labels == nil {
				continue
			}
			region := firstLabel(labels, regionLabels)
			zone := firstLabel(labels, zoneLabels)
			if region != "" {
				regionCount[region]++
			} else if zone != "" {
				if c, ok := LookupZone(zone); ok {
					regionCount[derivedRegionFromZone(zone, c)]++
				}
			}
			if zone != "" {
				zoneSet[zone] = struct{}{}
			}
		}

		for r := range regionCount {
			data.Regions = append(data.Regions, r)
		}
		sort.Strings(data.Regions)
		for z := range zoneSet {
			data.Zones = append(data.Zones, z)
		}
		sort.Strings(data.Zones)

		if len(regionCount) > 0 {
			best := dominantRegion(regionCount)
			coord, ok := Lookup(best)
			if !ok {
				if c, ok2 := LookupZone(best); ok2 {
					coord = c
					ok = true
				}
			}
			data.Region = best
			if ok {
				data.Provider = coord.Provider
				data.City = coord.City
				data.Lat = coord.Lat
				data.Lng = coord.Lng
				data.HasLocation = true
				data.LocatedNodes = regionCount[best]
				data.Source = "auto"
			}
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// applyConfigMap reads the kube-system/fleetsweeper ConfigMap and populates
// data from its lat/lng/site/notes/region keys when present and parseable.
// Returns true when a location was applied.
func applyConfigMap(ctx context.Context, client *kube.Client, data *Data) bool {
	cm, err := client.Clientset().CoreV1().ConfigMaps(configMapNamespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil || cm == nil {
		return false
	}
	lat, latOK := parseFloat(cm.Data["lat"])
	lng, lngOK := parseFloat(cm.Data["lng"])
	if !latOK || !lngOK {
		return false
	}
	if !validCoord(lat, lng) {
		return false
	}
	data.Lat = lat
	data.Lng = lng
	data.HasLocation = true
	data.Source = "configmap"
	data.Site = cm.Data["site"]
	data.Notes = cm.Data["notes"]
	if r := cm.Data["region"]; r != "" {
		data.Region = r
		if c, ok := Lookup(r); ok {
			data.Provider = c.Provider
			if data.City == "" {
				data.City = c.City
			}
		}
	}
	if data.City == "" {
		data.City = data.Site
	}
	return true
}

// applyNamespaceAnnotations reads the kube-system namespace's annotations
// for fleetsweeper.io/lat, /lng, /site, /notes and populates data when both
// coordinates are present and valid.
func applyNamespaceAnnotations(ctx context.Context, client *kube.Client, data *Data) bool {
	ns, err := client.Clientset().CoreV1().Namespaces().Get(ctx, configMapNamespace, metav1.GetOptions{})
	if err != nil || ns == nil || ns.Annotations == nil {
		return false
	}
	lat, latOK := parseFloat(ns.Annotations[annoLat])
	lng, lngOK := parseFloat(ns.Annotations[annoLng])
	if !latOK || !lngOK {
		return false
	}
	if !validCoord(lat, lng) {
		return false
	}
	data.Lat = lat
	data.Lng = lng
	data.HasLocation = true
	data.Source = "annotation"
	data.Site = ns.Annotations[annoSite]
	data.Notes = ns.Annotations[annoNotes]
	if data.City == "" {
		data.City = data.Site
	}
	return true
}

// parseFloat trims and parses a decimal string, returning ok=false on empty
// input or parse failure. Used for ConfigMap/annotation values which are
// always strings.
func parseFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// validCoord reports whether lat/lng fall inside the Earth's coordinate
// bounds. Anything else is operator error and should be ignored rather than
// dropped silently onto the globe.
func validCoord(lat, lng float64) bool {
	return lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180
}

// collectRegionsZones walks the node list once and records distinct region
// and zone labels. Shared between the auto-detect path and the manual
// override paths so the Regions/Zones fields are populated even when the
// final placement came from an annotation or ConfigMap.
func collectRegionsZones(items []corev1.Node, regionCount map[string]int, zoneSet map[string]struct{}) {
	for i := range items {
		labels := items[i].Labels
		if labels == nil {
			continue
		}
		region := firstLabel(labels, regionLabels)
		zone := firstLabel(labels, zoneLabels)
		if region != "" {
			regionCount[region]++
		}
		if zone != "" {
			zoneSet[zone] = struct{}{}
		}
	}
}

// sortedKeys returns the keys of a map[string]X as a deterministic slice.
// Implemented separately for the int-valued and struct{}-valued maps used
// by the scanner.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstLabel returns the value of the first label key from keys that is
// present and non-empty in labels.
func firstLabel(labels map[string]string, keys []string) string {
	for _, k := range keys {
		if v, ok := labels[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// dominantRegion picks the most-populous region from a count map. Ties
// break alphabetically so output is deterministic.
func dominantRegion(counts map[string]int) string {
	var best string
	bestN := -1
	for r, n := range counts {
		if n > bestN || (n == bestN && r < best) {
			best = r
			bestN = n
		}
	}
	return best
}

// derivedRegionFromZone returns the region key that LookupZone resolved to,
// extracted from the zone string itself when possible. We only use this as
// a counter key, so an approximation that groups zones of the same region
// is good enough.
func derivedRegionFromZone(zone string, _ Coord) string {
	if strings.HasSuffix(zone, "a") || strings.HasSuffix(zone, "b") || strings.HasSuffix(zone, "c") || strings.HasSuffix(zone, "d") || strings.HasSuffix(zone, "e") || strings.HasSuffix(zone, "f") {
		trimmed := zone[:len(zone)-1]
		if strings.HasSuffix(trimmed, "-") {
			trimmed = trimmed[:len(trimmed)-1]
		}
		return trimmed
	}
	return zone
}
