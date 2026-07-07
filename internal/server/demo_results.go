package server

import (
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// demoResults synthesizes per-cluster scanner results for the demo fleet so the
// real report engine (MAD outlier detection, cohort baselining, degraded
// coverage, findings, and the fleet score) runs end to end under serve --demo
// instead of being hand-faked. Values are role-based with deterministic
// per-cluster jitter, so distributions have real spread and the planted extremes
// surface as genuine outliers.
func demoResults() map[string]map[string]scanner.Result {
	pts := demoPoints()
	out := make(map[string]map[string]scanner.Result, len(pts))

	for _, p := range pts {
		c := p.Cluster
		st := p.status()
		nodes := demoNodeCount(c)
		healthy := demoHealthyNodes(c, st)
		cpu := demoCPU(st) + float64(jitter(c+"cpu", 5))
		mem := demoMem(st) + float64(jitter(c+"mem", 5))
		notReady := 0
		memPressure := 0
		if st == "critical" {
			notReady = 1
			memPressure = 2
		}
		unenforced := 0
		nsWithout := 0
		if st == "critical" || st == "degraded" {
			unenforced = 3 + jitter(c+"un", 2)
			nsWithout = 4 + jitter(c+"nw", 2)
		}

		data := map[string]map[string]any{
			"version": {"git_version": demoVersion(c), "minor": demoMinor(demoVersion(c))},
			"resources": {
				"node_count": nodes, "unschedulable_nodes": 0,
			},
			"node-health": {
				"node_count": nodes, "healthy_nodes": healthy, "unhealthy_nodes": nodes - healthy,
				"not_ready_nodes": notReady, "memory_pressure_nodes": memPressure,
			},
			"metrics": {
				"avg_cpu_percent": cpu, "avg_memory_percent": mem,
				"max_cpu_percent": cpu + 7, "max_memory_percent": mem + 6,
			},
			"events":           {"warning_events": demoEventCount(st) + jitter(c+"ev", 5)},
			"namespaces":       {"count": demoNSCount(c) + jitter(c+"ns", 3)},
			"services":         {"count": roleBase(c, 60, 24, 14) + jitter(c+"svc", 8)},
			"ingresses":        {"count": roleBase(c, 22, 9, 4) + jitter(c+"ing", 3)},
			"rbac":             {"cluster_role_count": 48 + jitter(c+"rb", 14)},
			"crds":             {"count": roleBase(c, 41, 22, 12) + jitter(c+"crd", 5)},
			"security":         {"enforced_count": roleBase(c, 30, 12, 9), "unenforced_count": unenforced},
			"network-policies": {"count": roleBase(c, 26, 10, 4), "namespaces_without_policies": nsWithout},
			"resource-quotas":  {"quota_count": 6 + jitter(c+"q", 4)},
		}

		m := make(map[string]scanner.Result, len(data))
		for name, d := range data {
			m[name] = scanner.Result{Scanner: name, Data: d}
		}
		out[c] = m
	}

	// Plant one blind read so the demo shows honest partial coverage rather
	// than a false all-clear: the metrics API is forbidden on one edge cluster.
	if m, ok := out["edge-lagos"]; ok {
		m["metrics"] = scanner.Result{
			Scanner: "metrics", State: scanner.StateErrored,
			Reason: "metrics.k8s.io API forbidden (RBAC)",
		}
	}

	return out
}

// demoTags assigns each cluster a cohort label by role so the cohort engine
// forms tagged cohorts (prod, retail, edge, nonprod) and reports within-cohort
// outliers for the cohorts large enough to be statistically meaningful.
func demoTags() map[string]string {
	tags := make(map[string]string)
	for _, p := range demoPoints() {
		tags[p.Cluster] = roleOf(p.Cluster)
	}
	return tags
}

// roleOf classifies a cluster by name prefix into a cohort label.
func roleOf(cluster string) string {
	switch {
	case startsWith(cluster, "prod-"):
		return "prod"
	case startsWith(cluster, "store-"), startsWith(cluster, "factory-"), startsWith(cluster, "warehouse-"):
		return "retail"
	case startsWith(cluster, "edge-"):
		return "edge"
	default:
		return "nonprod"
	}
}

// roleBase returns a base count by role tier: large for prod, medium for retail,
// small for edge and everything else, so cohorts separate cleanly on features.
func roleBase(cluster string, prod, retail, small int) int {
	switch roleOf(cluster) {
	case "prod":
		return prod
	case "retail":
		return retail
	default:
		return small
	}
}

// demoMinor extracts the Kubernetes minor version number from a git version
// string like "v1.31.3", returning 0 when it cannot be parsed.
func demoMinor(gitVersion string) int {
	parts := strings.Split(strings.TrimPrefix(gitVersion, "v"), ".")
	if len(parts) < 2 {
		return 0
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return n
}

// jitter returns a deterministic per-key integer in [-spread, spread] so demo
// distributions have real variance (a zero-variance field yields no outliers)
// while staying stable across server restarts.
func jitter(key string, spread int) int {
	if spread <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()%uint32(2*spread+1)) - spread
}
