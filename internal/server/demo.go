package server

// demoPoints returns a synthetic fleet of clusters scattered around the
// globe in a mix of health states, so the /globe UI can be demoed without
// any real Kubernetes clusters or scans. The composition is intentional:
// at least three critical clusters in different continents (so the pulsing
// rings are visible on every camera angle), a handful of degraded clusters,
// busy clusters in major regions, and a long tail of healthy small dots.
// Coordinates are real city centroids; cluster names mix cloud-style
// contexts and retail-style site names.
func demoPoints() []geoPoint {
	return []geoPoint{
		// Critical — pulsing red on the globe.
		{Cluster: "prod-us-east-1", Status: "critical", Provider: "AWS", Region: "us-east-1", City: "N. Virginia", Lat: 38.95, Lng: -77.46, Source: "auto", CriticalFindings: 3, WarningFindings: 12},
		{Cluster: "store-nyc-42", Status: "critical", Site: "Store #42, Times Square", City: "Store #42, Times Square", Lat: 40.7589, Lng: -73.9851, Source: "manual", CriticalFindings: 2, WarningFindings: 6},
		{Cluster: "factory-osaka", Status: "critical", Site: "Osaka Plant", City: "Osaka Plant", Lat: 34.6937, Lng: 135.5023, Source: "configmap", CriticalFindings: 1, WarningFindings: 4},
		{Cluster: "edge-johannesburg", Status: "critical", Provider: "Azure", Region: "southafricanorth", City: "Johannesburg", Lat: -26.20, Lng: 28.05, Source: "auto", CriticalFindings: 1, WarningFindings: 2},

		// Degraded — yellow.
		{Cluster: "prod-eu-central-1", Status: "degraded", Provider: "AWS", Region: "eu-central-1", City: "Frankfurt", Lat: 50.11, Lng: 8.68, Source: "auto", WarningFindings: 9},
		{Cluster: "staging-ap-southeast-1", Status: "degraded", Provider: "AWS", Region: "ap-southeast-1", City: "Singapore", Lat: 1.35, Lng: 103.82, Source: "auto", WarningFindings: 5},
		{Cluster: "store-london-soho", Status: "degraded", Site: "Store #8, Soho", City: "Store #8, Soho", Lat: 51.5074, Lng: -0.1278, Source: "annotation", WarningFindings: 3},
		{Cluster: "warehouse-sao-paulo", Status: "degraded", Site: "Warehouse SP-1", City: "Warehouse SP-1", Lat: -23.55, Lng: -46.63, Source: "configmap", WarningFindings: 4},

		// Busy — blue (healthy under load).
		{Cluster: "prod-us-west-2", Status: "busy", Provider: "AWS", Region: "us-west-2", City: "Oregon", Lat: 45.51, Lng: -122.68, Source: "auto"},
		{Cluster: "prod-europe-west2", Status: "busy", Provider: "GCP", Region: "europe-west2", City: "London", Lat: 51.50, Lng: -0.13, Source: "auto"},
		{Cluster: "prod-japaneast", Status: "busy", Provider: "Azure", Region: "japaneast", City: "Tokyo", Lat: 35.68, Lng: 139.69, Source: "auto"},
		{Cluster: "store-sydney-cbd", Status: "busy", Site: "Sydney CBD flagship", City: "Sydney CBD flagship", Lat: -33.87, Lng: 151.21, Source: "manual"},
		{Cluster: "prod-ap-south-1", Status: "busy", Provider: "AWS", Region: "ap-south-1", City: "Mumbai", Lat: 19.08, Lng: 72.88, Source: "auto"},

		// Healthy — green, the long tail.
		{Cluster: "dev-us-central1", Status: "healthy", Provider: "GCP", Region: "us-central1", City: "Iowa", Lat: 41.26, Lng: -95.93, Source: "auto"},
		{Cluster: "dev-canadacentral", Status: "healthy", Provider: "Azure", Region: "canadacentral", City: "Toronto", Lat: 43.65, Lng: -79.38, Source: "auto"},
		{Cluster: "dev-eu-north-1", Status: "healthy", Provider: "AWS", Region: "eu-north-1", City: "Stockholm", Lat: 59.33, Lng: 18.07, Source: "auto"},
		{Cluster: "staging-ap-northeast-2", Status: "healthy", Provider: "AWS", Region: "ap-northeast-2", City: "Seoul", Lat: 37.57, Lng: 126.98, Source: "auto"},
		{Cluster: "store-paris-12", Status: "healthy", Site: "Store #12, Champs-Élysées", City: "Store #12, Champs-Élysées", Lat: 48.8566, Lng: 2.3522, Source: "manual"},
		{Cluster: "store-dubai-mall", Status: "healthy", Site: "Dubai Mall outpost", City: "Dubai Mall outpost", Lat: 25.27, Lng: 55.30, Source: "manual"},
		{Cluster: "store-mexico-city", Status: "healthy", Site: "CDMX flagship", City: "CDMX flagship", Lat: 19.4326, Lng: -99.1332, Source: "manual"},
		{Cluster: "edge-buenos-aires", Status: "healthy", Site: "BA edge site", City: "BA edge site", Lat: -34.6037, Lng: -58.3816, Source: "manual"},
		{Cluster: "edge-lagos", Status: "healthy", Site: "Lagos edge site", City: "Lagos edge site", Lat: 6.5244, Lng: 3.3792, Source: "manual"},
		{Cluster: "dev-australiasoutheast", Status: "healthy", Provider: "GCP", Region: "australia-southeast1", City: "Sydney", Lat: -33.87, Lng: 151.21, Source: "auto"},
		{Cluster: "dev-southamerica-east1", Status: "healthy", Provider: "GCP", Region: "southamerica-east1", City: "São Paulo", Lat: -23.55, Lng: -46.63, Source: "auto"},
		{Cluster: "store-vancouver", Status: "healthy", Site: "Vancouver waterfront", City: "Vancouver waterfront", Lat: 49.2827, Lng: -123.1207, Source: "manual"},
		{Cluster: "store-honolulu", Status: "healthy", Site: "Honolulu beachfront", City: "Honolulu beachfront", Lat: 21.3069, Lng: -157.8583, Source: "manual"},
	}
}
