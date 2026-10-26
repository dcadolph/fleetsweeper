package server

import (
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoCluster is one cluster of the synthetic demo fleet: where it sits, which cohort it belongs
// to, and the size its scanner data is built around.
type demoCluster struct {
	// Name is the cluster's context name.
	Name string
	// Cohort is the cohort tag: prod, nonprod, sites, or edge.
	Cohort string
	// Source is how the globe places the cluster: auto (cloud region), configmap or annotation
	// (an in-cluster label the geo scanner reads), or manual (a stored location override).
	Source string
	// Provider is the cloud provider of an auto-placed cluster.
	Provider string
	// Region is the cloud region of an auto-placed cluster.
	Region string
	// City is the place name shown on the globe.
	City string
	// Site is the operator's site label for a configmap, annotation, or manual placement.
	Site string
	// Lat is the latitude.
	Lat float64
	// Lng is the longitude.
	Lng float64
	// Version is the Kubernetes version the cluster runs.
	Version string
}

// demoFleet returns the 26 clusters of the demo fleet: six production regions, seven
// non-production clusters, nine sites, and four edge clusters, on four continents.
func demoFleet() []demoCluster {
	return []demoCluster{
		{Name: "prod-us-east-1", Cohort: "prod", Source: "auto", Provider: "aws", Region: "us-east-1", City: "N. Virginia", Lat: 38.95, Lng: -77.46, Version: "v1.31.4"},
		{Name: "prod-us-west-2", Cohort: "prod", Source: "auto", Provider: "aws", Region: "us-west-2", City: "Oregon", Lat: 45.51, Lng: -122.68, Version: "v1.31.4"},
		{Name: "prod-eu-central-1", Cohort: "prod", Source: "auto", Provider: "aws", Region: "eu-central-1", City: "Frankfurt", Lat: 50.11, Lng: 8.68, Version: "v1.31.4"},
		{Name: "prod-europe-west2", Cohort: "prod", Source: "auto", Provider: "gcp", Region: "europe-west2", City: "London", Lat: 51.50, Lng: -0.13, Version: "v1.31.4"},
		{Name: "prod-japaneast", Cohort: "prod", Source: "auto", Provider: "azure", Region: "japaneast", City: "Tokyo", Lat: 35.68, Lng: 139.69, Version: "v1.31.4"},
		{Name: "prod-ap-south-1", Cohort: "prod", Source: "auto", Provider: "aws", Region: "ap-south-1", City: "Mumbai", Lat: 19.08, Lng: 72.88, Version: "v1.31.4"},

		{Name: "dev-us-central1", Cohort: "nonprod", Source: "auto", Provider: "gcp", Region: "us-central1", City: "Iowa", Lat: 41.26, Lng: -95.93, Version: "v1.31.4"},
		{Name: "dev-canadacentral", Cohort: "nonprod", Source: "auto", Provider: "azure", Region: "canadacentral", City: "Toronto", Lat: 43.65, Lng: -79.38, Version: "v1.31.4"},
		{Name: "dev-eu-north-1", Cohort: "nonprod", Source: "auto", Provider: "aws", Region: "eu-north-1", City: "Stockholm", Lat: 59.33, Lng: 18.07, Version: "v1.31.4"},
		{Name: "staging-ap-northeast-2", Cohort: "nonprod", Source: "auto", Provider: "aws", Region: "ap-northeast-2", City: "Seoul", Lat: 37.57, Lng: 126.98, Version: "v1.30.8"},
		{Name: "staging-ap-southeast-1", Cohort: "nonprod", Source: "auto", Provider: "aws", Region: "ap-southeast-1", City: "Singapore", Lat: 1.35, Lng: 103.82, Version: "v1.31.4"},
		{Name: "dev-australiasoutheast", Cohort: "nonprod", Source: "auto", Provider: "gcp", Region: "australia-southeast1", City: "Sydney", Lat: -33.87, Lng: 151.21, Version: "v1.31.4"},
		{Name: "dev-southamerica-east1", Cohort: "nonprod", Source: "auto", Provider: "gcp", Region: "southamerica-east1", City: "São Paulo", Lat: -23.55, Lng: -46.63, Version: "v1.31.4"},

		{Name: "site-osaka-1", Cohort: "sites", Source: "configmap", Site: "Osaka site 1", Lat: 34.69, Lng: 135.50, Version: "v1.31.4"},
		{Name: "site-london-8", Cohort: "sites", Source: "annotation", Site: "London site 8", Lat: 51.51, Lng: -0.13, Version: "v1.31.4"},
		{Name: "site-sao-paulo-1", Cohort: "sites", Source: "configmap", Site: "São Paulo site 1", Lat: -23.55, Lng: -46.63, Version: "v1.31.4"},
		{Name: "site-sydney-1", Cohort: "sites", Source: "manual", Site: "Sydney site 1", Lat: -33.87, Lng: 151.21, Version: "v1.31.4"},
		{Name: "site-paris-12", Cohort: "sites", Source: "manual", Site: "Paris site 12", Lat: 48.86, Lng: 2.35, Version: "v1.31.4"},
		{Name: "site-dubai-1", Cohort: "sites", Source: "manual", Site: "Dubai site 1", Lat: 25.27, Lng: 55.30, Version: "v1.31.4"},
		{Name: "site-mexico-city-1", Cohort: "sites", Source: "manual", Site: "Mexico City site 1", Lat: 19.43, Lng: -99.13, Version: "v1.31.4"},
		{Name: "site-vancouver-1", Cohort: "sites", Source: "manual", Site: "Vancouver site 1", Lat: 49.28, Lng: -123.12, Version: "v1.31.4"},
		{Name: "site-honolulu-1", Cohort: "sites", Source: "manual", Site: "Honolulu site 1", Lat: 21.31, Lng: -157.86, Version: "v1.31.4"},

		{Name: "edge-nyc-42", Cohort: "edge", Source: "manual", Site: "NYC edge 42", Lat: 40.76, Lng: -73.99, Version: "v1.31.4"},
		{Name: "edge-johannesburg", Cohort: "edge", Source: "auto", Provider: "azure", Region: "southafricanorth", City: "Johannesburg", Lat: -26.20, Lng: 28.05, Version: "v1.31.4"},
		{Name: "edge-buenos-aires", Cohort: "edge", Source: "manual", Site: "Buenos Aires edge", Lat: -34.60, Lng: -58.38, Version: "v1.31.4"},
		{Name: "edge-lagos", Cohort: "edge", Source: "manual", Site: "Lagos edge", Lat: 6.52, Lng: 3.38, Version: "v1.31.4"},
	}
}

// demoClusterNames returns the demo fleet's cluster names in table order.
func demoClusterNames() []string {
	fleet := demoFleet()
	out := make([]string, len(fleet))
	for i, c := range fleet {
		out[i] = c.Name
	}
	return out
}

// demoTags maps each demo cluster to its cohort.
func demoTags() map[string]string {
	tags := make(map[string]string, len(demoFleet()))
	for _, c := range demoFleet() {
		tags[c.Name] = c.Cohort
	}
	return tags
}

// demoGroups returns the demo's cluster groups, one per cohort.
func demoGroups() []store.GroupRecord {
	names := map[string]string{"prod": "production", "nonprod": "non-production", "sites": "sites", "edge": "edge"}
	members := map[string][]string{}
	for _, c := range demoFleet() {
		members[c.Cohort] = append(members[c.Cohort], c.Name)
	}
	out := make([]store.GroupRecord, 0, len(names))
	for _, cohort := range []string{"prod", "nonprod", "sites", "edge"} {
		out = append(out, store.GroupRecord{Name: names[cohort], Clusters: members[cohort]})
	}
	return out
}

// demoAlerts returns inbound alerts, AlertManager and Falco, firing and resolved, ending at now,
// so the Alerts page shows what live alert ingestion looks like.
func demoAlerts(now time.Time) []store.AlertRecord {
	mk := func(fp, cluster, status, name, sev, summary, source string, agoMin int) store.AlertRecord {
		at := now.Add(-time.Duration(agoMin) * time.Minute)
		return store.AlertRecord{
			Fingerprint: fp,
			Cluster:     cluster,
			Status:      status,
			AlertName:   name,
			Severity:    sev,
			Summary:     summary,
			StartsAt:    at,
			ReceivedAt:  at,
			Labels:      map[string]string{"source": source, "cluster": cluster, "severity": sev, "alertname": name},
			Annotations: map[string]string{"summary": summary},
		}
	}
	return []store.AlertRecord{
		mk("demo-al-1", "prod-us-east-1", "firing", "KubeMemoryPressure", "critical",
			"2 nodes have reported MemoryPressure for over 10 minutes.", "alertmanager", 8),
		mk("demo-al-2", "edge-nyc-42", "firing", "UnexpectedOutboundConnection", "critical",
			"A container opened an outbound connection to a host outside the allowlist.", "falco", 15),
		mk("demo-al-3", "site-osaka-1", "firing", "CertificateExpiringSoon", "warning",
			"Certificate ingress-tls-2 in pos expires in 12 days.", "alertmanager", 22),
		mk("demo-al-4", "prod-eu-central-1", "firing", "DeprecatedAPIInUse", "warning",
			"policy/v1beta1 PodDisruptionBudget is still in use before the next upgrade.", "alertmanager", 40),
		mk("demo-al-5", "site-london-8", "firing", "WriteBelowEtc", "warning",
			"A container process wrote under /etc at runtime.", "falco", 55),
		mk("demo-al-6", "prod-us-west-2", "resolved", "HighCPUThrottling", "warning",
			"CPU throttling cleared after the cluster autoscaled.", "alertmanager", 90),
	}
}
