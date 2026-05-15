package report

// criticalFields maps scanner names to field names whose divergence is critical.
var criticalFields = map[string]map[string]struct{}{
	"version":          {"git_version": {}, "major": {}},
	"security":         {"enforced_count": {}, "unenforced_count": {}},
	"rbac":             {"cluster_role_count": {}, "cluster_role_binding_count": {}},
	"network-policies": {"namespaces_without_policies": {}},
	"node-health":      {"unhealthy_nodes": {}, "memory_pressure_nodes": {}, "not_ready_nodes": {}},
	"metrics":           {"max_cpu_percent": {}, "max_memory_percent": {}},
	"workload-security": {"privileged_containers": {}, "host_network_pods": {}, "host_pid_pods": {}},
	"rbac-audit":        {"cluster_admin_bindings": {}, "wildcard_rules": {}},
}

// warningFields maps scanner names to field names whose divergence is a warning.
var warningFields = map[string]map[string]struct{}{
	"version":         {"minor": {}},
	"namespaces":      {"count": {}},
	"services":        {"count": {}},
	"resource-quotas": {"quota_count": {}, "namespaces_with_quotas": {}},
	"resources":       {"node_count": {}, "ready_nodes": {}, "unschedulable_nodes": {}},
	"node-health":       {"disk_pressure_nodes": {}, "pid_pressure_nodes": {}, "unschedulable_nodes": {}},
	"workload-security": {"run_as_root_containers": {}, "capability_additions": {}},
	"rbac-audit":        {"default_sa_bindings": {}},
	"image-audit":       {"latest_tag": {}, "no_digest": {}},
	"metrics":         {"avg_cpu_percent": {}, "avg_memory_percent": {}},
}

// applySeverity assigns severity levels to all divergences in a section based
// on the scanner name and field.
func applySeverity(scannerName string, section *SectionReport) {
	for i := range section.Divergences {
		section.Divergences[i].Severity = classifySeverity(scannerName, section.Divergences[i].Field)
	}
}

// classifySeverity determines the severity for a divergent field.
func classifySeverity(scannerName, field string) string {
	if fields, ok := criticalFields[scannerName]; ok {
		if _, ok := fields[field]; ok {
			return SeverityCritical
		}
	}
	if fields, ok := warningFields[scannerName]; ok {
		if _, ok := fields[field]; ok {
			return SeverityWarning
		}
	}
	return SeverityInfo
}
