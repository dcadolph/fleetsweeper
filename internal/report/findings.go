package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// Finding is a human-readable issue discovered across the fleet.
type Finding struct {
	// Title is a short description of the finding.
	Title string `json:"title"`
	// Description is a detailed explanation.
	Description string `json:"description"`
	// Severity is critical, warning, or info.
	Severity string `json:"severity"`
	// Cluster is the cluster this finding applies to, or "fleet" for cross-cluster.
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produced this finding.
	Scanner string `json:"scanner"`
}

// ClusterHealth summarizes a single cluster's overall state.
type ClusterHealth struct {
	// Name is the cluster context name.
	Name string `json:"name"`
	// Status is "healthy", "degraded", or "critical".
	Status string `json:"status"`
	// FindingCounts maps severity to count for this cluster.
	FindingCounts map[string]int `json:"finding_counts"`
	// KubernetesVersion is the cluster's k8s version.
	KubernetesVersion string `json:"kubernetes_version"`
	// NodeCount is the number of nodes.
	NodeCount int `json:"node_count"`
	// HealthyNodes is the number of healthy nodes.
	HealthyNodes int `json:"healthy_nodes"`
	// AvgCPU is the average CPU utilization percentage.
	AvgCPU float64 `json:"avg_cpu"`
	// AvgMemory is the average memory utilization percentage.
	AvgMemory float64 `json:"avg_memory"`
	// WarningEvents is the number of warning events.
	WarningEvents int `json:"warning_events"`
	// NamespaceCount is the number of namespaces.
	NamespaceCount int `json:"namespace_count"`
}

// GenerateFindings analyzes a report and produces human-readable findings.
func GenerateFindings(r *Report) []Finding {
	var findings []Finding
	findings = append(findings, versionFindings(r)...)
	findings = append(findings, healthFindings(r)...)
	findings = append(findings, metricsFindings(r)...)
	findings = append(findings, securityFindings(r)...)
	findings = append(findings, networkFindings(r)...)
	findings = append(findings, quotaFindings(r)...)
	findings = append(findings, eventFindings(r)...)
	findings = append(findings, namespaceFindings(r)...)
	findings = append(findings, rbacFindings(r)...)

	// Sort: critical first, then warning, then info.
	severityOrder := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	return findings
}

// GenerateClusterHealth builds per-cluster health summaries.
func GenerateClusterHealth(r *Report, findings []Finding) []ClusterHealth {
	var healths []ClusterHealth
	for _, cluster := range r.Clusters {
		h := ClusterHealth{
			Name:          cluster,
			Status:        "healthy",
			FindingCounts: map[string]int{SeverityCritical: 0, SeverityWarning: 0, SeverityInfo: 0},
		}
		for _, f := range findings {
			if f.Cluster == cluster || f.Cluster == "fleet" {
				h.FindingCounts[f.Severity]++
			}
		}
		if h.FindingCounts[SeverityCritical] > 0 {
			h.Status = "critical"
		} else if h.FindingCounts[SeverityWarning] > 0 {
			h.Status = "degraded"
		}

		h.KubernetesVersion = getStringField(r, "version", cluster, "git_version")
		h.NodeCount = getIntField(r, "node-health", cluster, "node_count")
		h.HealthyNodes = getIntField(r, "node-health", cluster, "healthy_nodes")
		h.AvgCPU = getFloatField(r, "metrics", cluster, "avg_cpu_percent")
		h.AvgMemory = getFloatField(r, "metrics", cluster, "avg_memory_percent")
		h.WarningEvents = getIntField(r, "events", cluster, "warning_events")
		h.NamespaceCount = getIntField(r, "namespaces", cluster, "count")

		healths = append(healths, h)
	}
	return healths
}

func versionFindings(r *Report) []Finding {
	sec := r.Sections["version"]
	if sec == nil || sec.Uniform {
		return nil
	}
	versions := make(map[string]string)
	for _, cluster := range r.Clusters {
		versions[cluster] = getStringField(r, "version", cluster, "git_version")
	}
	var findings []Finding
	ref := versions[r.Clusters[0]]
	for _, cluster := range r.Clusters[1:] {
		if versions[cluster] != ref {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is running a different Kubernetes version", cluster),
				Description: fmt.Sprintf("%s is on %s while the rest of the fleet is on %s.", cluster, versions[cluster], ref),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "version",
			})
		}
	}
	return findings
}

func healthFindings(r *Report) []Finding {
	sec := r.Sections["node-health"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		unhealthy := getIntField(r, "node-health", cluster, "unhealthy_nodes")
		memPressure := getIntField(r, "node-health", cluster, "memory_pressure_nodes")
		diskPressure := getIntField(r, "node-health", cluster, "disk_pressure_nodes")
		notReady := getIntField(r, "node-health", cluster, "not_ready_nodes")
		total := getIntField(r, "node-health", cluster, "node_count")

		if memPressure > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) under memory pressure", cluster, memPressure),
				Description: fmt.Sprintf("%d of %d nodes are reporting MemoryPressure=True. These nodes may be unable to schedule new pods and existing pods risk OOM kills.", memPressure, total),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "node-health",
			})
		}
		if diskPressure > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) under disk pressure", cluster, diskPressure),
				Description: fmt.Sprintf("%d of %d nodes are reporting DiskPressure=True. Pods may be evicted to free disk space.", diskPressure, total),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "node-health",
			})
		}
		if notReady > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) not ready", cluster, notReady),
				Description: fmt.Sprintf("%d of %d nodes are not reporting Ready=True. Workloads cannot be scheduled to these nodes.", notReady, total),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "node-health",
			})
		}
		if unhealthy == 0 && total > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s: all %d nodes healthy", cluster, total),
				Description: "All nodes are Ready with no pressure conditions.",
				Severity:    SeverityInfo,
				Cluster:     cluster,
				Scanner:     "node-health",
			})
		}
	}
	return findings
}

func metricsFindings(r *Report) []Finding {
	sec := r.Sections["metrics"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		avgMem := getFloatField(r, "metrics", cluster, "avg_memory_percent")
		maxMem := getFloatField(r, "metrics", cluster, "max_memory_percent")
		avgCPU := getFloatField(r, "metrics", cluster, "avg_cpu_percent")
		maxCPU := getFloatField(r, "metrics", cluster, "max_cpu_percent")
		maxMemNode := getStringField(r, "metrics", cluster, "max_memory_node")
		maxCPUNode := getStringField(r, "metrics", cluster, "max_cpu_node")

		if avgMem > 85 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is running critically low on memory (%.0f%% avg)", cluster, avgMem),
				Description: fmt.Sprintf("Average memory utilization is %.1f%% across all nodes. Peak is %.1f%% on %s. The cluster needs more memory capacity or workloads need to be rebalanced.", avgMem, maxMem, maxMemNode),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "metrics",
			})
		} else if avgMem > 70 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s memory utilization is elevated (%.0f%% avg)", cluster, avgMem),
				Description: fmt.Sprintf("Average memory utilization is %.1f%%. Peak is %.1f%% on %s.", avgMem, maxMem, maxMemNode),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "metrics",
			})
		}

		if avgCPU > 85 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is running critically high on CPU (%.0f%% avg)", cluster, avgCPU),
				Description: fmt.Sprintf("Average CPU utilization is %.1f%% across all nodes. Peak is %.1f%% on %s.", avgCPU, maxCPU, maxCPUNode),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "metrics",
			})
		} else if avgCPU > 70 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s CPU utilization is elevated (%.0f%% avg)", cluster, avgCPU),
				Description: fmt.Sprintf("Average CPU utilization is %.1f%%. Peak is %.1f%% on %s.", avgCPU, maxCPU, maxCPUNode),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "metrics",
			})
		}
	}
	return findings
}

func securityFindings(r *Report) []Finding {
	sec := r.Sections["security"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		unenforced := getIntField(r, "security", cluster, "unenforced_count")
		total := getIntField(r, "security", cluster, "namespace_count")
		if unenforced > 0 {
			pct := float64(unenforced) / math.Max(float64(total), 1) * 100
			sev := SeverityWarning
			if pct > 50 {
				sev = SeverityCritical
			}
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d namespace(s) without Pod Security enforcement", cluster, unenforced),
				Description: fmt.Sprintf("%d of %d namespaces (%.0f%%) have no Pod Security Standards enforce label. Pods in these namespaces can run with any privileges.", unenforced, total, pct),
				Severity:    sev,
				Cluster:     cluster,
				Scanner:     "security",
			})
		}
	}
	return findings
}

func networkFindings(r *Report) []Finding {
	sec := r.Sections["network-policies"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		without := getIntField(r, "network-policies", cluster, "namespaces_without_policies")
		if without > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d namespace(s) with no network policies", cluster, without),
				Description: fmt.Sprintf("%d namespaces have no NetworkPolicy resources. All pod-to-pod traffic is allowed in these namespaces.", without),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "network-policies",
			})
		}
	}
	return findings
}

func quotaFindings(r *Report) []Finding {
	sec := r.Sections["resource-quotas"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		quotas := getIntField(r, "resource-quotas", cluster, "namespaces_with_quotas")
		nsCount := getIntField(r, "namespaces", cluster, "count")
		if nsCount > 0 && quotas == 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has no resource quotas defined", cluster),
				Description: "No namespaces have ResourceQuota objects. There are no limits on resource consumption per namespace.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "resource-quotas",
			})
		}
	}
	return findings
}

func eventFindings(r *Report) []Finding {
	sec := r.Sections["events"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		warningCount := getIntField(r, "events", cluster, "warning_events")
		if warningCount > 50 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d warning events", cluster, warningCount),
				Description: fmt.Sprintf("The cluster has %d warning events. Check the events section below for details on the most common reasons.", warningCount),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "events",
			})
		} else if warningCount > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d warning event(s)", cluster, warningCount),
				Description: "Some warning events detected. Check the events section for details.",
				Severity:    SeverityInfo,
				Cluster:     cluster,
				Scanner:     "events",
			})
		}
	}
	return findings
}

func namespaceFindings(r *Report) []Finding {
	sec := r.Sections["namespaces"]
	if sec == nil || sec.Uniform {
		return nil
	}
	counts := make(map[string]int)
	for _, cluster := range r.Clusters {
		counts[cluster] = getIntField(r, "namespaces", cluster, "count")
	}
	var min, max int
	var minC, maxC string
	first := true
	for c, n := range counts {
		if first || n < min {
			min = n
			minC = c
		}
		if first || n > max {
			max = n
			maxC = c
		}
		first = false
	}
	if min != max {
		return []Finding{{
			Title:       "Namespace count varies across the fleet",
			Description: fmt.Sprintf("%s has %d namespaces while %s has %d. This may indicate missing deployments or environment drift.", minC, min, maxC, max),
			Severity:    SeverityWarning,
			Cluster:     "fleet",
			Scanner:     "namespaces",
		}}
	}
	return nil
}

func rbacFindings(r *Report) []Finding {
	sec := r.Sections["rbac"]
	if sec == nil || sec.Uniform {
		return nil
	}
	return []Finding{{
		Title:       "RBAC configuration differs across clusters",
		Description: "ClusterRoles, Roles, or their bindings differ between clusters. This may mean some clusters have more or fewer permissions than intended.",
		Severity:    SeverityWarning,
		Cluster:     "fleet",
		Scanner:     "rbac",
	}}
}

// getStringField extracts a string field from a cluster's scanner data.
func getStringField(r *Report, scannerName, cluster, field string) string {
	sec := r.Sections[scannerName]
	if sec == nil {
		return ""
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return ""
	}
	b, _ := json.Marshal(data)
	var m map[string]any
	json.Unmarshal(b, &m)
	s, _ := m[field].(string)
	return s
}

// getIntField extracts an integer field from a cluster's scanner data.
func getIntField(r *Report, scannerName, cluster, field string) int {
	sec := r.Sections[scannerName]
	if sec == nil {
		return 0
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return 0
	}
	b, _ := json.Marshal(data)
	var m map[string]any
	json.Unmarshal(b, &m)
	return int(toFloat64(m[field]))
}

// getFloatField extracts a float field from a cluster's scanner data.
func getFloatField(r *Report, scannerName, cluster, field string) float64 {
	sec := r.Sections[scannerName]
	if sec == nil {
		return 0
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return 0
	}
	b, _ := json.Marshal(data)
	var m map[string]any
	json.Unmarshal(b, &m)
	return toFloat64(m[field])
}
