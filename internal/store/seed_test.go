package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestSeedDemoDatabase creates a fully populated demo database at ~/Downloads/fleetsweeper-demo.db.
// Run with: go test -run TestSeedDemoDatabase ./internal/store/ -v
func TestSeedDemoDatabase(t *testing.T) { //nolint:funlen // Test function.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get home dir: %v", err)
	}
	downloads := filepath.Join(home, "Downloads")
	if _, err := os.Stat(downloads); err != nil {
		t.Skipf("skipping: %s not available (set up for local fixture generation)", downloads)
	}
	dbPath := filepath.Join(downloads, "fleetsweeper-demo.db")
	os.Remove(dbPath)

	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	clusters := []string{"prod-us-east", "prod-us-west", "prod-eu-central", "staging-us", "dev-local"}

	// Create groups.
	s.SaveGroup(ctx, "production", []string{"prod-us-east", "prod-us-west", "prod-eu-central"})
	s.SaveGroup(ctx, "non-production", []string{"staging-us", "dev-local"})

	// Simulate 5 scans over the past week with evolving data.
	for scanNum := 0; scanNum < 5; scanNum++ {
		results := make(map[string]map[string]scanner.Result, len(clusters))

		for _, cluster := range clusters {
			results[cluster] = buildClusterData(cluster, scanNum)
		}

		id, err := s.SaveScan(ctx, clusters, results)
		if err != nil {
			t.Fatalf("save scan %d: %v", scanNum, err)
		}
		t.Logf("scan %d: %s", scanNum, id)

		// Backdate the scan timestamp so trends are visible.
		daysAgo := (4 - scanNum) * 2
		ts := time.Now().Add(-time.Duration(daysAgo) * 24 * time.Hour).UTC().Format(time.RFC3339)
		s.db.ExecContext(ctx, "UPDATE scans SET timestamp = ? WHERE id = ?", ts, id)

		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("demo database written to %s", dbPath)
	t.Log("start server with: go run . serve --db ~/Downloads/fleetsweeper-demo.db")
}

// buildClusterData generates realistic scanner data for a cluster at a given scan iteration.
func buildClusterData(cluster string, scanNum int) map[string]scanner.Result { //nolint:funlen // Test function.
	r := make(map[string]scanner.Result)

	// Version: prod clusters on 1.31, staging drifts from 1.30 to 1.31 over time, dev stays on 1.29.
	ver := "v1.31.2"
	major, minor := "1", "31"
	platform := "linux/amd64"
	switch cluster {
	case "staging-us":
		if scanNum < 3 {
			ver = "v1.30.4"
			minor = "30"
		}
	case "dev-local":
		ver = "v1.29.1"
		minor = "29"
		platform = "linux/arm64"
	}
	r["version"] = scanner.Result{Scanner: "version", Data: map[string]any{
		"major": major, "minor": minor, "git_version": ver, "platform": platform,
	}}

	// Namespaces: prod has more, dev has fewer.
	nsCount := 12
	names := []string{"default", "kube-system", "kube-public", "monitoring", "app-prod", "ingress-nginx", "cert-manager", "logging", "istio-system", "argocd", "vault", "redis"}
	switch cluster {
	case "staging-us":
		nsCount = 8
		names = names[:8]
	case "dev-local":
		nsCount = 5
		names = names[:5]
	}
	r["namespaces"] = scanner.Result{Scanner: "namespaces", Data: map[string]any{
		"count": float64(nsCount), "names": names,
	}}

	// Services.
	svcCount := 24
	if cluster == "staging-us" {
		svcCount = 14
	} else if cluster == "dev-local" {
		svcCount = 6
	}
	r["services"] = scanner.Result{Scanner: "services", Data: map[string]any{
		"count": float64(svcCount),
	}}

	// Ingresses.
	ingCount := 8
	if cluster == "dev-local" {
		ingCount = 2
	}
	r["ingresses"] = scanner.Result{Scanner: "ingresses", Data: map[string]any{
		"count": float64(ingCount),
	}}

	// RBAC.
	crCount := 72
	if cluster == "dev-local" {
		crCount = 65
	}
	r["rbac"] = scanner.Result{Scanner: "rbac", Data: map[string]any{
		"cluster_role_count": float64(crCount), "role_count": float64(18),
		"cluster_role_binding_count": float64(54), "role_binding_count": float64(22),
	}}

	// Security: prod enforced, staging partially, dev not at all.
	enforced, unenforced := 10, 2
	switch cluster {
	case "staging-us":
		enforced, unenforced = 3, 5
	case "dev-local":
		enforced, unenforced = 0, 5
	}
	r["security"] = scanner.Result{Scanner: "security", Data: map[string]any{
		"namespace_count": float64(nsCount), "enforced_count": float64(enforced), "unenforced_count": float64(unenforced),
	}}

	// Network policies: prod has coverage, staging sparse, dev none.
	npCount, withPol, withoutPol := 15, 8, 4
	switch cluster {
	case "staging-us":
		npCount, withPol, withoutPol = 4, 3, 5
	case "dev-local":
		npCount, withPol, withoutPol = 0, 0, 5
	}
	r["network-policies"] = scanner.Result{Scanner: "network-policies", Data: map[string]any{
		"count": float64(npCount), "namespaces_with_policies": float64(withPol), "namespaces_without_policies": float64(withoutPol),
	}}

	// Resource quotas.
	quotaCount := 6
	if cluster == "dev-local" {
		quotaCount = 0
	} else if cluster == "staging-us" {
		quotaCount = 2
	}
	r["resource-quotas"] = scanner.Result{Scanner: "resource-quotas", Data: map[string]any{
		"quota_count": float64(quotaCount), "limit_range_count": float64(4), "namespaces_with_quotas": float64(quotaCount),
	}}

	// CRDs.
	crdCount := 42
	if cluster == "dev-local" {
		crdCount = 28
	}
	r["crds"] = scanner.Result{Scanner: "crds", Data: map[string]any{
		"count": float64(crdCount),
	}}

	// Node resources.
	nodeCount := 6
	readyNodes := 6
	unschedulable := 0
	switch cluster {
	case "staging-us":
		nodeCount = 3
		readyNodes = 3
	case "dev-local":
		nodeCount = 1
		readyNodes = 1
	case "prod-eu-central":
		if scanNum >= 3 {
			readyNodes = 5
			unschedulable = 1
		}
	}
	r["resources"] = scanner.Result{Scanner: "resources", Data: map[string]any{
		"node_count": float64(nodeCount), "ready_nodes": float64(readyNodes), "unschedulable_nodes": float64(unschedulable),
		"total_allocatable_cpu": fmt.Sprintf("%dm", nodeCount*4000), "total_allocatable_memory": fmt.Sprintf("%.1fGi", float64(nodeCount)*16.0),
	}}

	// Node health: prod-eu-central develops memory pressure over time.
	healthyNodes := nodeCount
	unhealthyNodes := 0
	memPressure := 0
	notReady := 0
	if cluster == "prod-eu-central" && scanNum >= 2 {
		memPressure = 1 + scanNum - 2
		if memPressure > nodeCount {
			memPressure = nodeCount
		}
		unhealthyNodes = memPressure
		healthyNodes = nodeCount - unhealthyNodes
		if scanNum >= 4 {
			notReady = 1
		}
	}
	r["node-health"] = scanner.Result{Scanner: "node-health", Data: map[string]any{
		"node_count": float64(nodeCount), "healthy_nodes": float64(healthyNodes), "unhealthy_nodes": float64(unhealthyNodes),
		"memory_pressure_nodes": float64(memPressure), "disk_pressure_nodes": float64(0),
		"pid_pressure_nodes": float64(0), "not_ready_nodes": float64(notReady), "unschedulable_nodes": float64(unschedulable),
	}}

	// Metrics: prod-eu-central CPU/memory climbs over time. Others stable.
	avgCPU, avgMem := 42.0, 55.0
	maxCPU, maxMem := 65.0, 70.0
	switch cluster {
	case "prod-eu-central":
		avgCPU = 45.0 + float64(scanNum)*10
		avgMem = 55.0 + float64(scanNum)*9
		maxCPU = 60.0 + float64(scanNum)*8
		maxMem = 65.0 + float64(scanNum)*8
	case "staging-us":
		avgCPU, avgMem = 35.0, 48.0
		maxCPU, maxMem = 55.0, 62.0
	case "dev-local":
		avgCPU, avgMem = 22.0, 38.0
		maxCPU, maxMem = 30.0, 45.0
	}
	r["metrics"] = scanner.Result{Scanner: "metrics", Data: map[string]any{
		"available": true, "node_count": float64(nodeCount),
		"avg_cpu_percent": avgCPU, "avg_memory_percent": avgMem,
		"max_cpu_percent": maxCPU, "max_memory_percent": maxMem,
		"max_cpu_node": "node-1", "max_memory_node": "node-2",
	}}

	// Events: prod-eu-central gets progressively more warnings.
	warningEvents := 5
	totalEvents := 100
	if cluster == "prod-eu-central" {
		warningEvents = 10 + scanNum*25
		totalEvents = 100 + scanNum*50
	} else if cluster == "dev-local" {
		warningEvents = 2
		totalEvents = 30
	}
	r["events"] = scanner.Result{Scanner: "events", Data: map[string]any{
		"total_events": float64(totalEvents), "warning_events": float64(warningEvents), "normal_events": float64(totalEvents - warningEvents),
	}}

	return r
}
