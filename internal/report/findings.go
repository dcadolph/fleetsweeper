package report

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Remediation describes the concrete action an operator can take to resolve a
// finding. Command is a kubectl invocation parameterized with the actual
// offending resource names so the user does not have to re-discover them.
// YAML, when present, is a multi-line baseline manifest that satisfies the
// requirement (for example a default-deny NetworkPolicy or a ResourceQuota).
// RunbookURL points at an internal runbook the operator has wired up; it is
// optional and may be empty.
type Remediation struct {
	// Command is a kubectl or related command that addresses the finding.
	Command string `json:"command,omitempty"`
	// YAML is a manifest snippet the operator can apply directly.
	YAML string `json:"yaml,omitempty"`
	// RunbookURL is an optional runbook link.
	RunbookURL string `json:"runbook_url,omitempty"`
}

// Finding is a human-readable issue discovered across the fleet. Findings name
// the affected resources (pods, nodes, bindings) inline so operators do not
// have to drill into the per-cluster JSON to identify what to fix.
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
	// Affected lists the offending resources (nodes, pods, bindings, images)
	// scoped to this finding. Empty when the finding has no specific noun.
	Affected []string `json:"affected,omitempty"`
	// Remediation is the suggested fix. Empty when no automated suggestion fits.
	Remediation *Remediation `json:"remediation,omitempty"`
}

// SystemNamespacePrefixes are the namespace name prefixes excluded from
// fleet-divergence findings. Cloud and add-on namespaces legitimately differ
// across providers; flagging them as drift drowns real signal.
var SystemNamespacePrefixes = []string{
	"kube-",
	"gke-",
	"eks-",
	"aks-",
	"cattle-",
	"istio-",
	"linkerd-",
	"cert-manager",
	"monitoring",
	"logging",
	"velero",
	"prometheus",
}

// SystemNamespaceExact are the namespace names treated as system regardless
// of prefix matching.
var SystemNamespaceExact = map[string]bool{
	"default":         true,
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// IsSystemNamespace reports whether a namespace name should be treated as a
// system namespace and therefore excluded from divergence findings.
func IsSystemNamespace(name string) bool {
	if SystemNamespaceExact[name] {
		return true
	}
	for _, p := range SystemNamespacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ClusterHealth summarizes a single cluster's overall state.
type ClusterHealth struct {
	// Name is the cluster context name.
	Name string `json:"name"`
	// Status is "healthy", "busy", "degraded", or "critical".
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
// At scale (more than 20 clusters), outlier-based findings replace pairwise
// comparison for version and namespace drift.
func GenerateFindings(r *Report) []Finding {
	var findings []Finding

	if len(r.Outliers) > 0 {
		findings = append(findings, outlierFindings(r)...)
	} else {
		findings = append(findings, versionFindings(r)...)
		findings = append(findings, namespaceFindings(r)...)
		findings = append(findings, rbacFindings(r)...)
	}

	findings = append(findings, nodeHealthFindings(r)...)
	findings = append(findings, capacityFindings(r)...)
	findings = append(findings, securityFindings(r)...)
	findings = append(findings, workloadSecFindings(r)...)
	findings = append(findings, rbacAuditFindings(r)...)
	findings = append(findings, imageAuditFindings(r)...)
	findings = append(findings, networkFindings(r)...)
	findings = append(findings, quotaFindings(r)...)
	findings = append(findings, eventFindings(r)...)
	findings = append(findings, certFindings(r)...)
	findings = append(findings, deprecatedAPIFindings(r)...)
	findings = append(findings, coverageFindings(r)...)
	findings = append(findings, admissionFindings(r)...)
	findings = append(findings, clusterInfoFindings(r)...)
	findings = append(findings, compositeBadDeployFindings(r)...)

	severityOrder := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	return findings
}

// outlierFindings converts OutlierResults into human-readable findings.
func outlierFindings(r *Report) []Finding {
	findings := make([]Finding, 0, len(r.Outliers))
	for _, o := range r.Outliers {
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("%s deviates from fleet norm on %s", o.Cluster, o.Field),
			Description: fmt.Sprintf("%s reports %s=%s while the fleet norm is %s (scanner: %s).", o.Cluster, o.Field, o.Value, o.FleetNorm, ScannerLabels[o.Scanner]),
			Severity:    o.Severity,
			Cluster:     o.Cluster,
			Scanner:     o.Scanner,
			Affected:    []string{o.Field},
		})
	}
	return findings
}

// GenerateClusterHealth builds per-cluster health summaries.
func GenerateClusterHealth(r *Report, findings []Finding) []ClusterHealth {
	healths := make([]ClusterHealth, 0, len(r.Clusters))
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

// versionFindings emits a single fleet-level finding when versions differ.
// Severity is calibrated to the Kubernetes version-skew policy: patch
// differences are info, single-minor skew is warning, larger skew is critical.
// Previously every version difference was unconditionally critical, which
// fired during every routine rolling upgrade.
func versionFindings(r *Report) []Finding {
	sec := r.Sections["version"]
	if sec == nil || sec.Uniform {
		return nil
	}
	versions := make(map[string]string, len(r.Clusters))
	uniqueVersions := make([]string, 0, len(r.Clusters))
	seen := make(map[string]bool)
	for _, cluster := range r.Clusters {
		v := getStringField(r, "version", cluster, "git_version")
		versions[cluster] = v
		if v != "" && !seen[v] {
			seen[v] = true
			uniqueVersions = append(uniqueVersions, v)
		}
	}
	if len(uniqueVersions) < 2 {
		return nil
	}

	severity := VersionSkewSeverity(uniqueVersions)
	if severity == SeverityInfo {
		return nil
	}

	sort.Strings(uniqueVersions)
	affected := make([]string, 0, len(versions))
	for _, c := range r.Clusters {
		if versions[c] != "" {
			affected = append(affected, fmt.Sprintf("%s=%s", c, versions[c]))
		}
	}
	sort.Strings(affected)

	return []Finding{{
		Title:       "Kubernetes version skew across fleet",
		Description: fmt.Sprintf("Fleet runs %d distinct versions: %s.", len(uniqueVersions), strings.Join(uniqueVersions, ", ")),
		Severity:    severity,
		Cluster:     "fleet",
		Scanner:     "version",
		Affected:    affected,
		Remediation: &Remediation{
			Command: "kubectl version --short",
		},
	}}
}

// nodeHealthFindings reports node-health problems with the specific affected
// node names included so operators can act without spelunking the JSON.
func nodeHealthFindings(r *Report) []Finding {
	sec := r.Sections["node-health"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		nodes := extractNodeNames(r, cluster, "node-health")
		memPressure := getIntField(r, "node-health", cluster, "memory_pressure_nodes")
		diskPressure := getIntField(r, "node-health", cluster, "disk_pressure_nodes")
		notReady := getIntField(r, "node-health", cluster, "not_ready_nodes")
		total := getIntField(r, "node-health", cluster, "node_count")

		if memPressure > 0 {
			affected := nodes.byCondition("MemoryPressure")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) under memory pressure", cluster, memPressure),
				Description: fmt.Sprintf("%d of %d nodes report MemoryPressure=True. Pods on these nodes risk OOM kills and the scheduler will avoid them.", memPressure, total),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "node-health",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s describe node %s", cluster, strings.Join(affected, " ")),
				},
			})
		}
		if diskPressure > 0 {
			affected := nodes.byCondition("DiskPressure")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) under disk pressure", cluster, diskPressure),
				Description: fmt.Sprintf("%d of %d nodes report DiskPressure=True. Pods may be evicted to free disk space.", diskPressure, total),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "node-health",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s describe node %s", cluster, strings.Join(affected, " ")),
				},
			})
		}
		if notReady > 0 {
			affected := nodes.notReady()
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d node(s) not ready", cluster, notReady),
				Description: fmt.Sprintf("%d of %d nodes are not reporting Ready=True. Workloads cannot be scheduled to these nodes.", notReady, total),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "node-health",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s describe node %s", cluster, strings.Join(affected, " ")),
				},
			})
		}
	}
	return findings
}

// nodeView is a thin wrapper that extracts per-node condition data from the
// node-health scanner output so we can name affected nodes in findings.
type nodeView struct {
	// Name is the node name.
	Name string
	// Ready reports the Ready condition value.
	Ready bool
	// Conditions are the condition types currently asserted on this node.
	Conditions []string
}

// nodeSet is a slice of node views with helpers to filter by condition.
type nodeSet []nodeView

// byCondition returns the names of nodes asserting the named negative condition.
func (ns nodeSet) byCondition(condition string) []string {
	var out []string
	for _, n := range ns {
		for _, c := range n.Conditions {
			if c == condition {
				out = append(out, n.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// notReady returns the names of nodes whose Ready condition is not true.
func (ns nodeSet) notReady() []string {
	var out []string
	for _, n := range ns {
		if !n.Ready {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// extractNodeNames reads the per-node detail in a scanner section. The
// node-health scanner emits a Nodes slice with name and conditions; we
// unmarshal generically so this function does not depend on the scanner
// package's concrete types.
func extractNodeNames(r *Report, cluster, scannerName string) nodeSet {
	sec := r.Sections[scannerName]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	rawNodes, _ := m["nodes"].([]any)
	out := make(nodeSet, 0, len(rawNodes))
	for _, raw := range rawNodes {
		nm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		nv := nodeView{}
		nv.Name, _ = nm["name"].(string)
		if v, ok := nm["ready"].(bool); ok {
			nv.Ready = v
		}
		if cs, ok := nm["conditions"].([]any); ok {
			for _, c := range cs {
				if s, ok := c.(string); ok {
					nv.Conditions = append(nv.Conditions, s)
				}
			}
		}
		out = append(out, nv)
	}
	return out
}

// capacityFindings generates findings from the capacity correlator.
func capacityFindings(r *Report) []Finding {
	var findings []Finding
	for _, ca := range r.Capacity {
		switch ca.Status {
		case "critical":
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is in critical state", ca.Cluster),
				Description: ca.Recommendation,
				Severity:    SeverityCritical,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		case "strained", "degraded":
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is degraded", ca.Cluster),
				Description: ca.Recommendation,
				Severity:    SeverityWarning,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		case "busy":
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is busy but healthy (CPU %.0f%%, memory %.0f%%)", ca.Cluster, ca.CPUUtilization, ca.MemoryUtilization),
				Description: ca.Recommendation,
				Severity:    SeverityInfo,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		default:
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s is healthy (CPU %.0f%%, memory %.0f%%)", ca.Cluster, ca.CPUUtilization, ca.MemoryUtilization),
				Description: ca.Recommendation,
				Severity:    SeverityInfo,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		}

		if ca.GroupDeviation != "" && !strings.HasPrefix(ca.GroupDeviation, "Within normal range") {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s deviates from group peers", ca.Cluster),
				Description: ca.GroupDeviation,
				Severity:    SeverityWarning,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		}
	}
	return findings
}

// securityFindings reports Pod Security Standard enforcement gaps.
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
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite", cluster),
				},
			})
		}
	}
	return findings
}

// networkFindings reports namespaces with no NetworkPolicy coverage and
// suggests a baseline default-deny manifest.
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
				Remediation: &Remediation{
					YAML: defaultDenyNetworkPolicyYAML,
				},
			})
		}
	}
	return findings
}

// defaultDenyNetworkPolicyYAML is a baseline manifest the UI can offer for
// the "no NetworkPolicy" finding. It denies all ingress and egress within
// the target namespace; operators can layer allow rules on top.
const defaultDenyNetworkPolicyYAML = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: REPLACE_WITH_NAMESPACE
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`

// quotaFindings reports clusters with no ResourceQuotas defined and ships a
// baseline manifest in the remediation block.
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
				Remediation: &Remediation{
					YAML: defaultResourceQuotaYAML,
				},
			})
		}
	}
	return findings
}

// defaultResourceQuotaYAML is a baseline manifest for the "no ResourceQuotas"
// finding.
const defaultResourceQuotaYAML = `apiVersion: v1
kind: ResourceQuota
metadata:
  name: default-quota
  namespace: REPLACE_WITH_NAMESPACE
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    pods: "100"
`

// eventFindings normalizes the warning-event count by cluster size so a
// 200-node cluster is not falsely flagged for the same threshold a 5-node
// cluster trips at. Top reasons are included when the scanner provided them.
func eventFindings(r *Report) []Finding {
	sec := r.Sections["events"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		warningCount := getIntField(r, "events", cluster, "warning_events")
		if warningCount == 0 {
			continue
		}
		nodes := getIntField(r, "node-health", cluster, "node_count")
		if nodes < 1 {
			nodes = 1
		}
		perNode := float64(warningCount) / float64(nodes)
		topReasons := topEventReasons(r, cluster, 3)

		sev := ""
		switch {
		case perNode > 20 || warningCount > 1000:
			sev = SeverityCritical
		case perNode > 5 || warningCount > 200:
			sev = SeverityWarning
		default:
			sev = SeverityInfo
		}
		desc := fmt.Sprintf("%d warning events in the last hour across %d node(s) (%.1f per node).", warningCount, nodes, perNode)
		if len(topReasons) > 0 {
			desc += " Top reasons: " + strings.Join(topReasons, ", ") + "."
		}
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("%s has %d warning event(s) in the last hour", cluster, warningCount),
			Description: desc,
			Severity:    sev,
			Cluster:     cluster,
			Scanner:     "events",
			Affected:    topReasons,
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s get events --field-selector type=Warning --sort-by=.lastTimestamp -A | tail -50", cluster),
			},
		})
	}
	return findings
}

// topEventReasons returns the top N warning event reasons by count for a
// cluster, formatted as "Reason (N)". Returns nil if the scanner did not
// emit a TopWarningReasons slice.
func topEventReasons(r *Report, cluster string, n int) []string {
	sec := r.Sections["events"]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	raw, _ := m["top_warning_reasons"].([]any)
	out := make([]string, 0, n)
	for _, r := range raw {
		entry, ok := r.(map[string]any)
		if !ok {
			continue
		}
		reason, _ := entry["reason"].(string)
		count := toFloat64(entry["count"])
		if reason == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s (%d)", reason, int(count)))
		if len(out) >= n {
			break
		}
	}
	return out
}

// namespaceFindings flags non-system namespace count divergence. System and
// cloud add-on namespaces are filtered through IsSystemNamespace so legitimate
// per-cloud namespace differences do not become recurring warnings.
func namespaceFindings(r *Report) []Finding {
	sec := r.Sections["namespaces"]
	if sec == nil {
		return nil
	}
	counts := make(map[string]int, len(r.Clusters))
	for _, cluster := range r.Clusters {
		counts[cluster] = countNonSystemNamespaces(r, cluster)
	}
	if len(counts) < 2 {
		return nil
	}

	var minVal, maxVal int
	var minC, maxC string
	first := true
	for c, n := range counts {
		if first || n < minVal {
			minVal = n
			minC = c
		}
		if first || n > maxVal {
			maxVal = n
			maxC = c
		}
		first = false
	}
	if maxVal-minVal <= 1 {
		return nil
	}
	return []Finding{{
		Title:       "Non-system namespace count varies across the fleet",
		Description: fmt.Sprintf("%s has %d non-system namespaces while %s has %d. Cloud and add-on namespaces are excluded from this comparison.", minC, minVal, maxC, maxVal),
		Severity:    SeverityWarning,
		Cluster:     "fleet",
		Scanner:     "namespaces",
		Affected:    []string{minC, maxC},
	}}
}

// countNonSystemNamespaces reads the namespace scanner's per-namespace list
// when present and counts those not in the system allowlist. Falls back to
// the bare count when the scanner did not emit names.
func countNonSystemNamespaces(r *Report, cluster string) int {
	sec := r.Sections["namespaces"]
	if sec == nil {
		return 0
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return 0
	}
	b, err := json.Marshal(data)
	if err != nil {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return 0
	}
	if raw, ok := m["namespaces"].([]any); ok {
		count := 0
		for _, n := range raw {
			entry, ok := n.(map[string]any)
			if !ok {
				continue
			}
			name, _ := entry["name"].(string)
			if !IsSystemNamespace(name) {
				count++
			}
		}
		return count
	}
	return int(toFloat64(m["count"]))
}

// rbacFindings emits a fleet-level warning when RBAC objects diverge.
// Naming offending bindings requires per-binding data from the rbac scanner;
// when only counts are available we leave the finding generic and let the
// rbac-audit scanner findings supply the specific offenders.
func rbacFindings(r *Report) []Finding {
	sec := r.Sections["rbac"]
	if sec == nil || sec.Uniform {
		return nil
	}
	return []Finding{{
		Title:       "RBAC configuration differs across clusters",
		Description: "ClusterRoles, Roles, or their bindings differ between clusters. See the rbac-audit findings for named offenders.",
		Severity:    SeverityWarning,
		Cluster:     "fleet",
		Scanner:     "rbac",
	}}
}

// workloadSecFindings emits per-cluster security findings naming the
// offending pods. The audit flagged that the previous implementation reported
// just a count without saying which pods were privileged.
func workloadSecFindings(r *Report) []Finding {
	sec := r.Sections["workload-security"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		risks := highRiskPods(r, cluster)
		privCount := getIntField(r, "workload-security", cluster, "privileged_containers")
		hostNet := getIntField(r, "workload-security", cluster, "host_network_pods")
		hostPID := getIntField(r, "workload-security", cluster, "host_pid_pods")
		rootCount := getIntField(r, "workload-security", cluster, "run_as_root_containers")
		capAdd := getIntField(r, "workload-security", cluster, "capability_additions")
		total := getIntField(r, "workload-security", cluster, "total_pods")

		if privCount > 0 {
			affected := filterRiskNames(risks, "privileged")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d privileged container(s)", cluster, privCount),
				Description: fmt.Sprintf("Privileged containers have full host access. Review whether these workloads genuinely require it. Total pods: %d.", total),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "workload-security",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + \"/\" + .metadata.name'", cluster),
				},
			})
		}
		if hostNet > 0 || hostPID > 0 {
			affected := append(filterRiskNames(risks, "host-network"), filterRiskNames(risks, "host-pid")...)
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has pods using host namespaces (network: %d, PID: %d)", cluster, hostNet, hostPID),
				Description: "Pods sharing the host network or PID namespace can see and interact with other processes and traffic on the node.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "workload-security",
				Affected:    dedup(affected),
			})
		}
		if rootCount > 0 && total > 0 {
			pct := float64(rootCount) / float64(total) * 100
			sev := SeverityInfo
			if pct > 50 {
				sev = SeverityWarning
			}
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d container(s) explicitly running as root (%.0f%%)", cluster, rootCount, pct),
				Description: "These containers have runAsUser=0 or runAsNonRoot=false set explicitly. Container escape vulnerabilities have higher impact when the workload is root.",
				Severity:    sev,
				Cluster:     cluster,
				Scanner:     "workload-security",
			})
		}
		if capAdd > 0 {
			affected := filterRiskNames(risks, "capabilities-add")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d container(s) with added Linux capabilities", cluster, capAdd),
				Description: "Containers requesting capabilities such as NET_ADMIN or SYS_PTRACE have elevated kernel access beyond the default set.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "workload-security",
				Affected:    affected,
			})
		}
	}
	return findings
}

// highRiskPod is the per-pod risk record extracted from the workloadsec
// scanner's HighRiskPods slice. Defined inline to avoid a hard dependency on
// the scanner package.
type highRiskPod struct {
	// Name is the namespace/pod[/container] identifier.
	Name string
	// Risks lists the risk tags attached to this pod.
	Risks []string
}

// highRiskPods extracts the HighRiskPods slice from a cluster's workloadsec
// data so finding messages can name specific offenders.
func highRiskPods(r *Report, cluster string) []highRiskPod {
	sec := r.Sections["workload-security"]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	raw, _ := m["high_risk_pods"].([]any)
	out := make([]highRiskPod, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ns, _ := entry["namespace"].(string)
		pod, _ := entry["pod"].(string)
		container, _ := entry["container"].(string)
		risksRaw, _ := entry["risks"].([]any)
		risks := make([]string, 0, len(risksRaw))
		for _, rr := range risksRaw {
			if s, ok := rr.(string); ok {
				risks = append(risks, s)
			}
		}
		out = append(out, highRiskPod{
			Name:  fmt.Sprintf("%s/%s/%s", ns, pod, container),
			Risks: risks,
		})
	}
	return out
}

// filterRiskNames returns the names of pods carrying the given risk tag, capped
// at 10 entries with an "and N more" suffix when truncated.
func filterRiskNames(pods []highRiskPod, tag string) []string {
	var out []string
	extra := 0
	for _, p := range pods {
		for _, r := range p.Risks {
			if strings.HasPrefix(r, tag) {
				if len(out) < 10 {
					out = append(out, p.Name)
				} else {
					extra++
				}
				break
			}
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("...and %d more", extra))
	}
	return out
}

// dedup returns s with duplicates removed, preserving order.
func dedup(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// rbacAuditFindings names the offending bindings and supplies parameterized
// kubectl remediation rather than asking the operator to re-discover names.
func rbacAuditFindings(r *Report) []Finding {
	sec := r.Sections["rbac-audit"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		risk := riskBindings(r, cluster)
		adminBindings := getIntField(r, "rbac-audit", cluster, "cluster_admin_bindings")
		wildcardRules := getIntField(r, "rbac-audit", cluster, "wildcard_rules")
		defaultSA := getIntField(r, "rbac-audit", cluster, "default_sa_bindings")

		if adminBindings > 0 {
			affected := filterBindingsByRisk(risk, "cluster-admin-to-non-system")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d non-system cluster-admin binding(s)", cluster, adminBindings),
				Description: "ClusterRoleBindings granting cluster-admin to non-system principals give unrestricted access to every resource in the cluster.",
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "rbac-audit",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s get clusterrolebinding %s -o yaml", cluster, strings.Join(affected, " ")),
				},
			})
		}
		if wildcardRules > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d RBAC rule(s) with wildcard permissions", cluster, wildcardRules),
				Description: "Rules using '*' for verbs, resources, or apiGroups grant broader access than most workloads need.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "rbac-audit",
			})
		}
		if defaultSA > 0 {
			affected := filterBindingsByRisk(risk, "grants-to-default-sa")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d binding(s) granting permissions to a default service account", cluster, defaultSA),
				Description: "The default service account is used by any pod that does not specify a different one. Granting it permissions means all unattributed workloads inherit them.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "rbac-audit",
				Affected:    affected,
			})
		}
	}
	return findings
}

// riskBinding is the per-binding record extracted from the rbac-audit scanner.
type riskBinding struct {
	// Name is the binding name.
	Name string
	// Kind is ClusterRoleBinding or RoleBinding.
	Kind string
	// Namespace is empty for ClusterRoleBinding.
	Namespace string
	// Risks lists the risk tags attached.
	Risks []string
}

// riskBindings extracts the rbac-audit scanner's risk_bindings slice.
func riskBindings(r *Report, cluster string) []riskBinding {
	sec := r.Sections["rbac-audit"]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	raw, _ := m["risk_bindings"].([]any)
	out := make([]riskBinding, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rb := riskBinding{}
		rb.Name, _ = entry["name"].(string)
		rb.Kind, _ = entry["kind"].(string)
		rb.Namespace, _ = entry["namespace"].(string)
		risksRaw, _ := entry["risks"].([]any)
		for _, rr := range risksRaw {
			if s, ok := rr.(string); ok {
				rb.Risks = append(rb.Risks, s)
			}
		}
		out = append(out, rb)
	}
	return out
}

// filterBindingsByRisk returns the names of bindings tagged with the named
// risk, capped at 10 entries.
func filterBindingsByRisk(bs []riskBinding, risk string) []string {
	var out []string
	extra := 0
	for _, b := range bs {
		for _, r := range b.Risks {
			if r == risk {
				if len(out) < 10 {
					out = append(out, b.Name)
				} else {
					extra++
				}
				break
			}
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("...and %d more", extra))
	}
	return out
}

// imageAuditFindings names the offending images so operators can pin or
// update them directly.
func imageAuditFindings(r *Report) []Finding {
	sec := r.Sections["image-audit"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		risks := imageRisks(r, cluster)
		latestTag := getIntField(r, "image-audit", cluster, "latest_tag")
		noDigest := getIntField(r, "image-audit", cluster, "no_digest")
		total := getIntField(r, "image-audit", cluster, "total_containers")

		if latestTag > 0 {
			affected := filterImagesByRisk(risks, "latest-tag")
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d container(s) using :latest or no tag", cluster, latestTag),
				Description: fmt.Sprintf("Out of %d containers, %d use :latest or omit a tag. Without a pinned tag, rollbacks and audits are unreliable.", total, latestTag),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "image-audit",
				Affected:    affected,
			})
		}
		if noDigest > 0 && total > 0 {
			pct := float64(noDigest) / float64(total) * 100
			sev := SeverityInfo
			if pct > 80 {
				sev = SeverityWarning
			}
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d container(s) without digest pins (%.0f%%)", cluster, noDigest, pct),
				Description: "Images without @sha256: digest pins can change content without changing the tag. Pinning digests ensures reproducible deployments.",
				Severity:    sev,
				Cluster:     cluster,
				Scanner:     "image-audit",
			})
		}
	}
	return findings
}

// imageRisk is the per-image record extracted from the image-audit scanner.
type imageRisk struct {
	// Image is the image reference (registry/name:tag).
	Image string
	// Where is "namespace/pod/container".
	Where string
	// Risks lists the risk tags attached.
	Risks []string
}

// imageRisks extracts the image-audit scanner's image_risks slice.
func imageRisks(r *Report, cluster string) []imageRisk {
	sec := r.Sections["image-audit"]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	raw, _ := m["image_risks"].([]any)
	out := make([]imageRisk, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ir := imageRisk{}
		ir.Image, _ = entry["image"].(string)
		ns, _ := entry["namespace"].(string)
		pod, _ := entry["pod"].(string)
		container, _ := entry["container"].(string)
		ir.Where = fmt.Sprintf("%s/%s/%s", ns, pod, container)
		risksRaw, _ := entry["risks"].([]any)
		for _, rr := range risksRaw {
			if s, ok := rr.(string); ok {
				ir.Risks = append(ir.Risks, s)
			}
		}
		out = append(out, ir)
	}
	return out
}

// filterImagesByRisk returns "image @ location" strings for images with the
// given risk tag, capped at 10 entries.
func filterImagesByRisk(images []imageRisk, risk string) []string {
	var out []string
	extra := 0
	for _, ir := range images {
		for _, r := range ir.Risks {
			if r == risk {
				if len(out) < 10 {
					out = append(out, fmt.Sprintf("%s @ %s", ir.Image, ir.Where))
				} else {
					extra++
				}
				break
			}
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("...and %d more", extra))
	}
	return out
}

// certFindings reports TLS certificates expiring soon. Each finding names the
// offending cert (namespace/secret or webhook config/webhook) and gives a
// kubectl command that surfaces the full Secret or webhook configuration.
func certFindings(r *Report) []Finding {
	sec := r.Sections["certs"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		data, ok := sec.PerCluster[cluster]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		raw, _ := m["certs"].([]any)
		var critical, warning []string
		for _, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := entry["name"].(string)
			ns, _ := entry["namespace"].(string)
			kind, _ := entry["kind"].(string)
			days := int(toFloat64(entry["days_remaining"]))
			label := name
			if ns != "" {
				label = ns + "/" + name
			}
			if kind != "" {
				label = kind + " " + label
			}
			label = fmt.Sprintf("%s (%d days)", label, days)
			switch {
			case days < 7:
				critical = append(critical, label)
			case days < 30:
				warning = append(warning, label)
			}
		}
		if len(critical) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d certificate(s) expiring in fewer than 7 days", cluster, len(critical)),
				Description: "These TLS certificates will expire imminently. Renew them before they break webhooks, ingress, or metrics endpoints.",
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "certs",
				Affected:    capList(critical, 10),
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s get secret -A --field-selector type=kubernetes.io/tls", cluster),
				},
			})
		}
		if len(warning) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d certificate(s) expiring within 30 days", cluster, len(warning)),
				Description: "Schedule renewals now to avoid expiry-driven outages.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "certs",
				Affected:    capList(warning, 10),
			})
		}
	}
	return findings
}

// deprecatedAPIFindings reports in-use deprecated APIs by removal version.
// Each entry names the apiVersion, kind, and instance count so operators
// know exactly what they need to migrate before the next minor upgrade.
func deprecatedAPIFindings(r *Report) []Finding {
	sec := r.Sections["deprecated-apis"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		data, ok := sec.PerCluster[cluster]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		raw, _ := m["deprecated"].([]any)
		if len(raw) == 0 {
			continue
		}
		var affected []string
		for _, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			apiVersion, _ := entry["api_version"].(string)
			kind, _ := entry["kind"].(string)
			removedIn, _ := entry["removed_in"].(string)
			instanceCount := int(toFloat64(entry["instance_count"]))
			affected = append(affected, fmt.Sprintf("%s %s (%d instances, removed in %s)", apiVersion, kind, instanceCount, removedIn))
		}
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("%s uses %d deprecated API version(s)", cluster, len(raw)),
			Description: "These API versions have been deprecated or removed in newer Kubernetes minor releases. Migrate before the next upgrade or workloads will fail.",
			Severity:    SeverityWarning,
			Cluster:     cluster,
			Scanner:     "deprecated-apis",
			Affected:    capList(affected, 10),
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s get --raw /metrics 2>/dev/null | grep apiserver_requested_deprecated_apis", cluster),
			},
		})
	}
	return findings
}

// coverageFindings reports replicated workloads lacking PDB or HPA. Operators
// learn about these gaps during incidents otherwise; the named workloads
// here are immediately fixable with one PDB/HPA manifest each.
func coverageFindings(r *Report) []Finding {
	sec := r.Sections["workload-coverage"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		data, ok := sec.PerCluster[cluster]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		raw, _ := m["gaps"].([]any)
		var missingPDB, missingHPA []string
		for _, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			ns, _ := entry["namespace"].(string)
			name, _ := entry["name"].(string)
			kind, _ := entry["kind"].(string)
			hasPDB, _ := entry["has_pdb"].(bool)
			hasHPA, _ := entry["has_hpa"].(bool)
			label := fmt.Sprintf("%s %s/%s", kind, ns, name)
			if !hasPDB {
				missingPDB = append(missingPDB, label)
			}
			if !hasHPA {
				missingHPA = append(missingHPA, label)
			}
		}
		if len(missingPDB) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d replicated workload(s) without a PodDisruptionBudget", cluster, len(missingPDB)),
				Description: "Voluntary disruptions (node drain, kubectl drain, autoscaler) can take all replicas of these workloads down simultaneously.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "workload-coverage",
				Affected:    capList(missingPDB, 10),
				Remediation: &Remediation{
					YAML: defaultPDBYAML,
				},
			})
		}
		if len(missingHPA) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d replicated workload(s) without a HorizontalPodAutoscaler", cluster, len(missingHPA)),
				Description: "These workloads cannot scale with load. If they are CPU- or memory-bound, expect throttling or OOMKills under traffic spikes.",
				Severity:    SeverityInfo,
				Cluster:     cluster,
				Scanner:     "workload-coverage",
				Affected:    capList(missingHPA, 10),
			})
		}
	}
	return findings
}

// defaultPDBYAML is a baseline PodDisruptionBudget manifest the UI can offer
// for the "missing PDB" finding.
const defaultPDBYAML = `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: REPLACE_WITH_WORKLOAD
  namespace: REPLACE_WITH_NAMESPACE
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: REPLACE_WITH_APP_LABEL
`

// admissionFindings surfaces broken or expiring admission webhooks. A
// failing webhook with failurePolicy=Fail can take admission offline cluster-
// wide. Each finding names the offending Configuration/Webhook.
func admissionFindings(r *Report) []Finding {
	sec := r.Sections["admission"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		data, ok := sec.PerCluster[cluster]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		raw, _ := m["webhooks"].([]any)
		var unhealthy, expiring []string
		for _, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cfg, _ := entry["configuration"].(string)
			whName, _ := entry["webhook"].(string)
			svc, _ := entry["service"].(string)
			healthy, _ := entry["endpoints_healthy"].(bool)
			failurePolicy, _ := entry["failure_policy"].(string)
			caDays := int(toFloat64(entry["ca_bundle_days_remaining"]))
			label := cfg + "/" + whName
			if !healthy && svc != "" {
				unhealthy = append(unhealthy, fmt.Sprintf("%s (service %s, failurePolicy=%s)", label, svc, failurePolicy))
			}
			if caDays >= 0 && caDays < 30 {
				expiring = append(expiring, fmt.Sprintf("%s (CA expires in %d days)", label, caDays))
			}
		}
		if len(unhealthy) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d admission webhook(s) with no healthy endpoints", cluster, len(unhealthy)),
				Description: "When failurePolicy=Fail, every API request matching these webhooks will be rejected. Even with failurePolicy=Ignore, mutations and validations are silently skipped.",
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "admission",
				Affected:    capList(unhealthy, 10),
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s get pods -A -l app=<webhook-service-app>", cluster),
				},
			})
		}
		if len(expiring) > 0 {
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("%s has %d admission webhook(s) with CA bundles expiring soon", cluster, len(expiring)),
				Description: "When a webhook CA bundle expires, the apiserver refuses to talk to the webhook. Renew or rotate before the listed deadlines.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "admission",
				Affected:    capList(expiring, 10),
			})
		}
	}
	return findings
}

// clusterInfoFindings flags within-cluster drift in OS image, kernel, runtime,
// or kubelet versions. Multiple distinct values signals mid-upgrade state or
// stale AMIs that should be tracked.
func clusterInfoFindings(r *Report) []Finding {
	sec := r.Sections["cluster-info"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		data, ok := sec.PerCluster[cluster]
		if !ok {
			continue
		}
		b, err := json.Marshal(data)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		hasDrift, _ := m["has_drift"].(bool)
		if !hasDrift {
			continue
		}
		var details []string
		for _, k := range []string{"os_images", "kernel_versions", "runtime_versions", "kubelet_versions"} {
			arr, _ := m[k].([]any)
			if len(arr) > 1 {
				vals := make([]string, 0, len(arr))
				for _, v := range arr {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
				details = append(details, fmt.Sprintf("%s: %s", k, strings.Join(vals, ", ")))
			}
		}
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("%s has node-level platform drift", cluster),
			Description: "Different nodes report different platform identities. Common cause: rolling node-pool replacement, stale AMI, or partially-completed upgrade.",
			Severity:    SeverityWarning,
			Cluster:     cluster,
			Scanner:     "cluster-info",
			Affected:    details,
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s get nodes -o wide", cluster),
			},
		})
	}
	return findings
}

// compositeBadDeployFindings correlates three independent signals — image
// risks, restart/pull events, and workload security risks — into a single
// critical finding per cluster. When the same namespace appears in all three
// the most likely root cause is a recent bad deploy; flagging it once at
// critical beats three disjoint info-level mentions.
func compositeBadDeployFindings(r *Report) []Finding {
	images := r.Sections["image-audit"]
	events := r.Sections["events"]
	if images == nil || events == nil {
		return nil
	}
	var findings []Finding
	badReasons := map[string]bool{
		"Failed":             true,
		"BackOff":            true,
		"CrashLoopBackOff":   true,
		"FailedScheduling":   true,
		"Killing":            true,
		"Pulling":            true,
		"FailedCreatePodSandBox": true,
	}
	for _, cluster := range r.Clusters {
		imgNS := namespacesWithImageRisk(r, cluster)
		evNS := namespacesWithEventReasons(r, cluster, badReasons)
		wsNS := namespacesWithWorkloadRisk(r, cluster)

		intersect := map[string]struct{}{}
		for ns := range imgNS {
			if _, ok := evNS[ns]; ok {
				if _, ok := wsNS[ns]; ok {
					intersect[ns] = struct{}{}
				}
			}
		}
		if len(intersect) == 0 {
			continue
		}
		names := make([]string, 0, len(intersect))
		for ns := range intersect {
			names = append(names, ns)
		}
		sort.Strings(names)
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("%s shows bad-deploy signals in %d namespace(s)", cluster, len(names)),
			Description: "Image risks (mutable tags or no-digest), failure-related warning events, and workload-security risks all overlap on the same namespace. This pattern matches a recently rolled-out workload that is failing.",
			Severity:    SeverityCritical,
			Cluster:     cluster,
			Scanner:     "image-audit",
			Affected:    names,
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s -n %s get pods,events --sort-by=.lastTimestamp", cluster, names[0]),
			},
		})
	}
	return findings
}

// namespacesWithImageRisk returns the set of namespaces in a cluster that
// have at least one risky image (latest tag or no digest).
func namespacesWithImageRisk(r *Report, cluster string) map[string]struct{} {
	out := make(map[string]struct{})
	risks := imageRisks(r, cluster)
	for _, ir := range risks {
		ns := ""
		parts := strings.SplitN(ir.Where, "/", 2)
		if len(parts) > 0 {
			ns = parts[0]
		}
		if ns != "" {
			out[ns] = struct{}{}
		}
	}
	return out
}

// namespacesWithEventReasons returns the namespaces whose warning events
// include any of the supplied reasons.
func namespacesWithEventReasons(r *Report, cluster string, reasons map[string]bool) map[string]struct{} {
	out := make(map[string]struct{})
	sec := r.Sections["events"]
	if sec == nil {
		return out
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return out
	}
	b, err := json.Marshal(data)
	if err != nil {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return out
	}
	rec, _ := m["recent_warnings"].([]any)
	for _, item := range rec {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		reason, _ := entry["reason"].(string)
		ns, _ := entry["namespace"].(string)
		if reasons[reason] && ns != "" {
			out[ns] = struct{}{}
		}
	}
	return out
}

// namespacesWithWorkloadRisk returns the namespaces with at least one
// high-risk pod in the workload-security scanner output.
func namespacesWithWorkloadRisk(r *Report, cluster string) map[string]struct{} {
	out := make(map[string]struct{})
	pods := highRiskPods(r, cluster)
	for _, p := range pods {
		parts := strings.SplitN(p.Name, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			out[parts[0]] = struct{}{}
		}
	}
	return out
}

// capList returns the slice capped at limit with an "and N more" suffix when
// truncated. Used to keep finding output readable on wide fleets.
func capList(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	out := make([]string, 0, limit+1)
	out = append(out, items[:limit]...)
	out = append(out, fmt.Sprintf("...and %d more", len(items)-limit))
	return out
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
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
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
	b, err := json.Marshal(data)
	if err != nil {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return 0
	}
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
	b, err := json.Marshal(data)
	if err != nil {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return 0
	}
	return toFloat64(m[field])
}
