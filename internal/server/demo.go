package server

import (
	"sort"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoScanID is the synthetic scan identifier returned in demo mode.
// Stable across calls so the dashboard and globe can deep-link into it.
const demoScanID = "demo-scan-0001"

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

// demoTimestamp returns a stable timestamp for the synthetic scan so the UI
// shows "Last scan: a few minutes ago" rather than a moving target every poll.
func demoTimestamp() time.Time {
	return time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Minute)
}

// demoScanRecord returns the synthetic ScanRecord exposed by handleListScans
// and handleGetScan when the server is in demo mode and the underlying store
// has no real scans.
func demoScanRecord() store.ScanRecord {
	pts := demoPoints()
	clusters := make([]string, len(pts))
	for i, p := range pts {
		clusters[i] = p.Cluster
	}
	return store.ScanRecord{
		ID:        demoScanID,
		Timestamp: demoTimestamp(),
		Clusters:  clusters,
		Scanners:  []string{"version", "node-health", "metrics", "events", "workload-security", "rbac-audit", "image-audit", "network-policies", "security", "certs", "deprecated-apis", "workload-coverage", "admission", "geo"},
	}
}

// demoReport returns a fully synthesized *report.Report aligned with the
// demoPoints fleet. Every page that consumes the report — Dashboard,
// Findings, Heatmap, Cluster detail, Capacity — gets coherent data so the
// demo experience is end-to-end, not just a globe.
func demoReport() *report.Report {
	pts := demoPoints()
	clusters := make([]string, len(pts))
	for i, p := range pts {
		clusters[i] = p.Cluster
	}

	// Run the real report engine over a synthetic fleet so the demo exercises
	// MAD outlier detection, cohort baselining, and degraded coverage instead
	// of hand-faked sections. Build populates Sections, Outliers, Cohorts,
	// Degraded, ClusterHealths, Capacity, and the fleet score for real.
	r := report.Build(clusters, demoResults(), report.BuildOptions{ClusterTags: demoTags()})
	r.Timestamp = demoTimestamp().Format(time.RFC3339)

	// Layer the curated incident narratives on top of the engine findings so
	// the Findings page keeps its specific stories next to the live outliers
	// and cohort drift the engine surfaced. Re-derive health and score from the
	// combined set so the numbers reconcile.
	r.Findings = append(r.Findings, demoFindings(pts)...)
	sortBySeverity(r.Findings)
	r.ClusterHealths = report.GenerateClusterHealth(r, r.Findings)
	r.FleetScore = report.ComputeFleetScore(r)
	r.Summary.CriticalCount = countSeverity(r.Findings, report.SeverityCritical)
	r.Summary.WarningCount = countSeverity(r.Findings, report.SeverityWarning)

	return r
}

// sortBySeverity orders findings critical-first so the demo Findings page leads
// with what matters.
func sortBySeverity(fs []report.Finding) {
	order := map[string]int{report.SeverityCritical: 0, report.SeverityWarning: 1, report.SeverityInfo: 2}
	sort.SliceStable(fs, func(i, j int) bool { return order[fs[i].Severity] < order[fs[j].Severity] })
}

// status normalizes the legacy "strained" label so consumers can match the
// four-tier vocabulary the rest of the codebase uses.
func (g geoPoint) status() string {
	if g.Status == "strained" {
		return "degraded"
	}
	return g.Status
}

// demoFindings builds the per-cluster findings for the synthetic fleet.
// Critical clusters get multi-finding stories that read like real incidents;
// degraded clusters get a single warning each; busy and healthy clusters are
// silent so the UI lights up where it matters.
func demoFindings(pts []geoPoint) []report.Finding {
	var out []report.Finding
	for _, p := range pts {
		switch p.status() {
		case "critical":
			out = append(out, criticalFindingsFor(p)...)
		case "degraded":
			out = append(out, degradedFindingsFor(p)...)
		case "busy":
			out = append(out, report.Finding{
				Title:       p.Cluster + " is busy but healthy (CPU 72%, memory 68%)",
				Description: "Utilization is elevated but no pressure conditions or restart spikes. Watch headroom; no action required yet.",
				Severity:    report.SeverityInfo, Cluster: p.Cluster, Scanner: "metrics",
			})
		}
	}
	return out
}

// criticalFindingsFor returns a small bundle of believable critical findings
// for one cluster. The wording is intentionally specific so the demo doesn't
// read like lorem ipsum.
func criticalFindingsFor(p geoPoint) []report.Finding {
	cluster := p.Cluster
	switch cluster {
	case "prod-us-east-1":
		return []report.Finding{
			{
				Title:       cluster + " has 2 node(s) under memory pressure",
				Description: "2 of 18 nodes report MemoryPressure=True. Pods on these nodes risk OOM kills and the scheduler will avoid them.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "node-health",
				Affected:    []string{"ip-10-0-12-44.ec2.internal", "ip-10-0-19-188.ec2.internal"},
				Remediation: &report.Remediation{Command: "kubectl --context " + cluster + " describe node ip-10-0-12-44.ec2.internal ip-10-0-19-188.ec2.internal"},
			},
			{
				Title:       cluster + " has 3 privileged container(s)",
				Description: "Privileged containers have full host access. Review whether these workloads genuinely require it.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "workload-security",
				Affected: []string{"observability/node-agent/agent", "security/falco/falco", "kube-system/csi-driver/driver"},
			},
			{
				Title:       cluster + " has 7 warning event(s) per node in the last hour",
				Description: "126 warning events in the last hour across 18 nodes. Top reasons: BackOff (52), FailedScheduling (31), Killing (18).",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "events",
				Remediation: &report.Remediation{Command: "kubectl --context " + cluster + " get events --field-selector type=Warning --sort-by=.lastTimestamp -A | tail -50"},
			},
		}
	case "store-nyc-42":
		return []report.Finding{
			{
				Title:       cluster + " shows bad-deploy signals in 1 namespace(s)",
				Description: "Image risks (no digest), failure-related warning events, and workload-security risks all overlap on the same namespace. Likely a recently rolled-out workload that is failing.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "image-audit",
				Affected:    []string{"pos-system"},
				Remediation: &report.Remediation{Command: "kubectl --context " + cluster + " -n pos-system get pods,events --sort-by=.lastTimestamp"},
			},
			{
				Title:       cluster + " has 1 certificate(s) expiring in fewer than 7 days",
				Description: "TLS certificate for the in-store payment webhook will expire imminently.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "certs",
				Affected: []string{"Secret pos-system/payments-tls (4 days)"},
			},
		}
	case "factory-osaka":
		return []report.Finding{
			{
				Title:       cluster + " has 1 admission webhook(s) with no healthy endpoints",
				Description: "ValidatingWebhookConfiguration policy-engine/scc has zero ready endpoints. With failurePolicy=Fail, admission is broken cluster-wide.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "admission",
				Affected: []string{"policy-engine/scc (service policy-engine/webhook, failurePolicy=Fail)"},
			},
		}
	case "edge-johannesburg":
		return []report.Finding{
			{
				Title:       cluster + " has 1 node(s) not ready",
				Description: "1 of 3 nodes is not reporting Ready=True. Workloads cannot be scheduled to it.",
				Severity:    report.SeverityCritical, Cluster: cluster, Scanner: "node-health",
				Affected:    []string{"node-az-c-3"},
				Remediation: &report.Remediation{Command: "kubectl --context " + cluster + " describe node node-az-c-3"},
			},
		}
	}
	return nil
}

// degradedFindingsFor returns a single warning-level finding per degraded
// cluster, enough to populate the Findings page without overwhelming it.
func degradedFindingsFor(p geoPoint) []report.Finding {
	cluster := p.Cluster
	switch cluster {
	case "prod-eu-central-1":
		return []report.Finding{{
			Title:       cluster + " uses 2 deprecated API version(s)",
			Description: "Migrate before the next Kubernetes minor upgrade or workloads will fail to admission.",
			Severity:    report.SeverityWarning, Cluster: cluster, Scanner: "deprecated-apis",
			Affected: []string{"policy/v1beta1 PodDisruptionBudget (12 instances, removed in 1.25)", "autoscaling/v2beta2 HorizontalPodAutoscaler (8 instances, removed in 1.26)"},
		}}
	case "staging-ap-southeast-1":
		return []report.Finding{{
			Title:       cluster + " has 4 replicated workload(s) without a PodDisruptionBudget",
			Description: "Voluntary disruptions can take all replicas of these workloads down simultaneously.",
			Severity:    report.SeverityWarning, Cluster: cluster, Scanner: "workload-coverage",
			Affected: []string{"Deployment payments/api", "Deployment cart/api", "Deployment search/web", "StatefulSet cache/redis"},
		}}
	case "store-london-soho":
		return []report.Finding{{
			Title:       cluster + " has 5 namespace(s) without Pod Security enforcement",
			Description: "5 of 14 namespaces (36%) have no Pod Security Standards enforce label.",
			Severity:    report.SeverityWarning, Cluster: cluster, Scanner: "security",
			Remediation: &report.Remediation{Command: "kubectl --context " + cluster + " label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite"},
		}}
	case "warehouse-sao-paulo":
		return []report.Finding{{
			Title:       cluster + " has 3 admission webhook(s) with CA bundles expiring soon",
			Description: "Renew or rotate the listed CA bundles before the deadlines.",
			Severity:    report.SeverityWarning, Cluster: cluster, Scanner: "admission",
			Affected: []string{"policy-engine/policy (CA expires in 17 days)", "policy-engine/mutate (CA expires in 17 days)", "ingress-nginx/admission (CA expires in 23 days)"},
		}}
	}
	return nil
}

// countSeverity tallies findings of a given severity.
func countSeverity(fs []report.Finding, sev string) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// demoVersion returns a plausible Kubernetes version per cluster so the
// "version skew" story across clusters lines up with one minor lagging.
func demoVersion(cluster string) string {
	switch cluster {
	case "prod-us-east-1", "prod-us-west-2", "prod-eu-central-1", "prod-europe-west2", "prod-japaneast", "prod-ap-south-1":
		return "v1.31.3"
	case "store-nyc-42", "store-london-soho", "store-sydney-cbd", "factory-osaka", "warehouse-sao-paulo":
		return "v1.30.6"
	case "edge-johannesburg", "edge-buenos-aires", "edge-lagos":
		return "v1.29.10"
	default:
		return "v1.31.2"
	}
}

// demoNodeCount returns a believable node count per cluster shape.
func demoNodeCount(cluster string) int {
	switch {
	case startsWith(cluster, "prod-"):
		return 18
	case startsWith(cluster, "staging-"):
		return 8
	case startsWith(cluster, "store-"), startsWith(cluster, "factory-"), startsWith(cluster, "warehouse-"):
		return 3
	case startsWith(cluster, "edge-"):
		return 3
	default:
		return 5
	}
}

// demoHealthyNodes derives a "ready" count from the cluster's status.
func demoHealthyNodes(cluster, status string) int {
	total := demoNodeCount(cluster)
	switch status {
	case "critical":
		return total - 2
	case "degraded":
		return total - 1
	default:
		return total
	}
}

// demoCPU / demoMem produce plausible utilization figures per status tier
// so the gauges show meaningful color spread on the dashboard.
func demoCPU(status string) float64 {
	switch status {
	case "critical":
		return 91
	case "degraded":
		return 78
	case "busy":
		return 72
	default:
		return 42
	}
}

func demoMem(status string) float64 {
	switch status {
	case "critical":
		return 88
	case "degraded":
		return 75
	case "busy":
		return 68
	default:
		return 51
	}
}

// demoEventCount produces a warning-event count per cluster status.
func demoEventCount(status string) int {
	switch status {
	case "critical":
		return 126
	case "degraded":
		return 41
	case "busy":
		return 12
	default:
		return 2
	}
}

// demoNSCount makes namespace counts vary realistically.
func demoNSCount(cluster string) int {
	switch {
	case startsWith(cluster, "prod-"):
		return 34
	case startsWith(cluster, "staging-"):
		return 18
	default:
		return 12
	}
}

// startsWith is a small helper so we don't pull in strings for one use.
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// demoFleetTrends returns synthetic fleet-wide trends with twelve historical
// points each, so the trend page lights up without any real scan history.
// The shape mixes worsening, improving, and stable directions so reviewers
// see the full UI vocabulary on the first paint.
func demoFleetTrends() []report.FleetTrend {
	now := demoTimestamp()
	step := 6 * time.Hour
	scanID := func(i int) string {
		return demoScanID + "-h" + itoa(i)
	}
	makePoints := func(values []float64) []report.TrendPoint {
		pts := make([]report.TrendPoint, len(values))
		for i, v := range values {
			pts[i] = report.TrendPoint{
				Timestamp: now.Add(-time.Duration(len(values)-1-i) * step),
				ScanID:    scanID(i),
				Value:     v,
			}
		}
		return pts
	}
	return []report.FleetTrend{
		{
			Scanner:    "events",
			Field:      "warning_events",
			Direction:  report.TrendWorsening,
			Confidence: "high",
			RSquared:   0.82,
			Points:     makePoints([]float64{38, 41, 44, 47, 52, 59, 67, 74, 83, 91, 102, 118}),
		},
		{
			Scanner:    "metrics",
			Field:      "avg_memory_percent",
			Direction:  report.TrendWorsening,
			Confidence: "high",
			RSquared:   0.74,
			Points:     makePoints([]float64{58, 59, 61, 62, 63, 65, 67, 69, 71, 73, 75, 77}),
		},
		{
			Scanner:    "node-health",
			Field:      "memory_pressure_nodes",
			Direction:  report.TrendWorsening,
			Confidence: "low",
			RSquared:   0.41,
			Points:     makePoints([]float64{0, 0, 1, 0, 1, 1, 2, 1, 2, 2, 3, 2}),
		},
		{
			Scanner:    "security",
			Field:      "unenforced_count",
			Direction:  report.TrendImproving,
			Confidence: "high",
			RSquared:   0.88,
			Points:     makePoints([]float64{19, 19, 18, 17, 17, 15, 14, 12, 11, 9, 8, 7}),
		},
		{
			Scanner:    "metrics",
			Field:      "avg_cpu_percent",
			Direction:  report.TrendStable,
			Confidence: "high",
			RSquared:   0.06,
			Points:     makePoints([]float64{61, 64, 60, 63, 62, 65, 61, 63, 64, 62, 63, 64}),
		},
	}
}

// demoOutliers returns synthetic outliers consistent with the fleet shape:
// edge clusters lagging on Kubernetes version, prod-us-east-1 well above the
// fleet warning-event median, store-nyc-42 with an anomalous restart count.
func demoOutliers() []report.OutlierResult {
	return []report.OutlierResult{
		{
			Cluster:   "edge-johannesburg",
			Field:     "version",
			Value:     "v1.29.10",
			FleetNorm: "v1.31.3",
			Scanner:   "version",
			Severity:  report.SeverityWarning,
		},
		{
			Cluster:   "edge-buenos-aires",
			Field:     "version",
			Value:     "v1.29.10",
			FleetNorm: "v1.31.3",
			Scanner:   "version",
			Severity:  report.SeverityWarning,
		},
		{
			Cluster:   "prod-us-east-1",
			Field:     "warning_events",
			Value:     "126",
			FleetNorm: "12",
			Deviation: 4.7,
			Scanner:   "events",
			Severity:  report.SeverityCritical,
		},
		{
			Cluster:   "factory-osaka",
			Field:     "ready_webhooks",
			Value:     "3",
			FleetNorm: "4",
			Deviation: 3.4,
			Scanner:   "admission",
			Severity:  report.SeverityCritical,
		},
		{
			Cluster:   "store-nyc-42",
			Field:     "restart_count",
			Value:     "47",
			FleetNorm: "2",
			Deviation: 5.1,
			Scanner:   "events",
			Severity:  report.SeverityCritical,
		},
	}
}

// itoa is a tiny base-10 formatter so demoFleetTrends does not need to pull
// in strconv just to suffix a scan-id index.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
