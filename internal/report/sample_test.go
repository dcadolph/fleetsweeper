package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestGenerateSampleHTML writes a sample HTML report to ~/Downloads for visual inspection.
// Run with: go test -run TestGenerateSampleHTML ./internal/report/
func TestGenerateSampleHTML(t *testing.T) { //nolint:funlen // Test function.
	clusters := []string{"prod-us-east", "prod-us-west", "staging-eu"}

	results := map[string]map[string]scanner.Result{
		"prod-us-east": {
			"events": {Scanner: "events", Data: map[string]any{
				"total_events": 142, "warning_events": 8, "normal_events": 134,
				"top_warning_reasons": []map[string]any{
					{"reason": "BackOff", "count": 5, "event_count": 3},
					{"reason": "FailedScheduling", "count": 3, "event_count": 2},
				},
			}},
			"version": {Scanner: "version", Data: map[string]any{
				"major": "1", "minor": "31", "git_version": "v1.31.2", "platform": "linux/amd64",
			}},
			"namespaces": {Scanner: "namespaces", Data: map[string]any{
				"count": 12, "names": []string{"default", "kube-system", "kube-public", "monitoring", "app-prod", "ingress-nginx", "cert-manager", "logging", "istio-system", "argocd", "vault", "redis"},
			}},
			"services": {Scanner: "services", Data: map[string]any{
				"count": 24,
			}},
			"ingresses": {Scanner: "ingresses", Data: map[string]any{
				"count": 8,
			}},
			"rbac": {Scanner: "rbac", Data: map[string]any{
				"cluster_role_count": 72, "role_count": 18,
				"cluster_role_binding_count": 54, "role_binding_count": 22,
			}},
			"security": {Scanner: "security", Data: map[string]any{
				"namespace_count": 12, "enforced_count": 10, "unenforced_count": 2,
			}},
			"network-policies": {Scanner: "network-policies", Data: map[string]any{
				"count": 15, "namespaces_with_policies": 8, "namespaces_without_policies": 4,
			}},
			"resource-quotas": {Scanner: "resource-quotas", Data: map[string]any{
				"quota_count": 6, "limit_range_count": 4, "namespaces_with_quotas": 6,
			}},
			"crds": {Scanner: "crds", Data: map[string]any{
				"count": 42,
			}},
			"resources": {Scanner: "resources", Data: map[string]any{
				"node_count": 6, "ready_nodes": 6, "unschedulable_nodes": 0,
				"total_allocatable_cpu": "24000m", "total_allocatable_memory": "96.0Gi",
			}},
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": 6, "healthy_nodes": 6, "unhealthy_nodes": 0,
				"memory_pressure_nodes": 0, "disk_pressure_nodes": 0,
				"pid_pressure_nodes": 0, "not_ready_nodes": 0, "unschedulable_nodes": 0,
			}},
			"metrics": {Scanner: "metrics", Data: map[string]any{
				"available": true, "node_count": 6,
				"avg_cpu_percent": 42.3, "avg_memory_percent": 58.1,
				"max_cpu_percent": 67.2, "max_memory_percent": 72.4,
				"max_cpu_node": "node-3", "max_memory_node": "node-3",
			}},
		},
		"prod-us-west": {
			"events": {Scanner: "events", Data: map[string]any{
				"total_events": 98, "warning_events": 3, "normal_events": 95,
				"top_warning_reasons": []map[string]any{
					{"reason": "Unhealthy", "count": 2, "event_count": 1},
					{"reason": "BackOff", "count": 1, "event_count": 1},
				},
			}},
			"version": {Scanner: "version", Data: map[string]any{
				"major": "1", "minor": "31", "git_version": "v1.31.2", "platform": "linux/amd64",
			}},
			"namespaces": {Scanner: "namespaces", Data: map[string]any{
				"count": 12, "names": []string{"default", "kube-system", "kube-public", "monitoring", "app-prod", "ingress-nginx", "cert-manager", "logging", "istio-system", "argocd", "vault", "redis"},
			}},
			"services": {Scanner: "services", Data: map[string]any{
				"count": 24,
			}},
			"ingresses": {Scanner: "ingresses", Data: map[string]any{
				"count": 8,
			}},
			"rbac": {Scanner: "rbac", Data: map[string]any{
				"cluster_role_count": 72, "role_count": 18,
				"cluster_role_binding_count": 54, "role_binding_count": 22,
			}},
			"security": {Scanner: "security", Data: map[string]any{
				"namespace_count": 12, "enforced_count": 10, "unenforced_count": 2,
			}},
			"network-policies": {Scanner: "network-policies", Data: map[string]any{
				"count": 15, "namespaces_with_policies": 8, "namespaces_without_policies": 4,
			}},
			"resource-quotas": {Scanner: "resource-quotas", Data: map[string]any{
				"quota_count": 6, "limit_range_count": 4, "namespaces_with_quotas": 6,
			}},
			"crds": {Scanner: "crds", Data: map[string]any{
				"count": 42,
			}},
			"resources": {Scanner: "resources", Data: map[string]any{
				"node_count": 6, "ready_nodes": 6, "unschedulable_nodes": 0,
				"total_allocatable_cpu": "24000m", "total_allocatable_memory": "96.0Gi",
			}},
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": 6, "healthy_nodes": 6, "unhealthy_nodes": 0,
				"memory_pressure_nodes": 0, "disk_pressure_nodes": 0,
				"pid_pressure_nodes": 0, "not_ready_nodes": 0, "unschedulable_nodes": 0,
			}},
			"metrics": {Scanner: "metrics", Data: map[string]any{
				"available": true, "node_count": 6,
				"avg_cpu_percent": 38.7, "avg_memory_percent": 55.2,
				"max_cpu_percent": 61.0, "max_memory_percent": 68.9,
				"max_cpu_node": "node-1", "max_memory_node": "node-5",
			}},
		},
		"staging-eu": {
			"events": {Scanner: "events", Data: map[string]any{
				"total_events": 487, "warning_events": 156, "normal_events": 331,
				"top_warning_reasons": []map[string]any{
					{"reason": "OOMKilling", "count": 68, "event_count": 23},
					{"reason": "FailedScheduling", "count": 42, "event_count": 18},
					{"reason": "BackOff", "count": 31, "event_count": 12},
					{"reason": "Evicted", "count": 15, "event_count": 8},
				},
			}},
			"version": {Scanner: "version", Data: map[string]any{
				"major": "1", "minor": "30", "git_version": "v1.30.4", "platform": "linux/arm64",
			}},
			"namespaces": {Scanner: "namespaces", Data: map[string]any{
				"count": 8, "names": []string{"default", "kube-system", "kube-public", "monitoring", "app-staging", "ingress-nginx", "cert-manager", "logging"},
			}},
			"services": {Scanner: "services", Data: map[string]any{
				"count": 14,
			}},
			"ingresses": {Scanner: "ingresses", Data: map[string]any{
				"count": 4,
			}},
			"rbac": {Scanner: "rbac", Data: map[string]any{
				"cluster_role_count": 68, "role_count": 12,
				"cluster_role_binding_count": 48, "role_binding_count": 14,
			}},
			"security": {Scanner: "security", Data: map[string]any{
				"namespace_count": 8, "enforced_count": 3, "unenforced_count": 5,
			}},
			"network-policies": {Scanner: "network-policies", Data: map[string]any{
				"count": 4, "namespaces_with_policies": 3, "namespaces_without_policies": 5,
			}},
			"resource-quotas": {Scanner: "resource-quotas", Data: map[string]any{
				"quota_count": 2, "limit_range_count": 1, "namespaces_with_quotas": 2,
			}},
			"crds": {Scanner: "crds", Data: map[string]any{
				"count": 38,
			}},
			"resources": {Scanner: "resources", Data: map[string]any{
				"node_count": 3, "ready_nodes": 2, "unschedulable_nodes": 1,
				"total_allocatable_cpu": "12000m", "total_allocatable_memory": "48.0Gi",
			}},
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": 3, "healthy_nodes": 1, "unhealthy_nodes": 2,
				"memory_pressure_nodes": 2, "disk_pressure_nodes": 1,
				"pid_pressure_nodes": 0, "not_ready_nodes": 1, "unschedulable_nodes": 1,
			}},
			"metrics": {Scanner: "metrics", Data: map[string]any{
				"available": true, "node_count": 3,
				"avg_cpu_percent": 78.4, "avg_memory_percent": 91.6,
				"max_cpu_percent": 94.2, "max_memory_percent": 97.8,
				"max_cpu_node": "node-1", "max_memory_node": "node-2",
			}},
		},
	}

	rpt := Build(clusters, results)
	html, err := RenderHTML(rpt)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get home dir: %v", err)
	}
	downloads := filepath.Join(home, "Downloads")
	if _, err := os.Stat(downloads); err != nil {
		t.Skipf("skipping: %s not available (set up for local fixture generation)", downloads)
	}
	outPath := filepath.Join(downloads, "fleetsweeper-sample-report.html")
	if err := os.WriteFile(outPath, html, 0o644); err != nil {
		t.Fatalf("write html: %v", err)
	}
	t.Logf("sample report written to %s", outPath)
}
