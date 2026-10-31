package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

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
		memPressure, memObs := observeInt(r, "node-health", cluster, "memory_pressure_nodes")
		diskPressure, diskObs := observeInt(r, "node-health", cluster, "disk_pressure_nodes")
		notReady, notReadyObs := observeInt(r, "node-health", cluster, "not_ready_nodes")
		total, _ := observeInt(r, "node-health", cluster, "node_count")

		if memObs.seen() && memPressure > 0 {
			affected := nodes.byCondition("MemoryPressure")
			findings = append(findings, Finding{
				Rule:        "node-health/memory-pressure",
				Title:       fmt.Sprintf("%s has %d node(s) under memory pressure", cluster, memPressure),
				Description: fmt.Sprintf("%d of %d nodes report MemoryPressure=True. Pods on these nodes risk OOM kills and the scheduler will avoid them.", memPressure, total) + memObs.note(),
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "node-health",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s describe node %s", cluster, strings.Join(affected, " ")),
				},
			})
		}
		if diskObs.seen() && diskPressure > 0 {
			affected := nodes.byCondition("DiskPressure")
			findings = append(findings, Finding{
				Rule:        "node-health/disk-pressure",
				Title:       fmt.Sprintf("%s has %d node(s) under disk pressure", cluster, diskPressure),
				Description: fmt.Sprintf("%d of %d nodes report DiskPressure=True. Pods may be evicted to free disk space.", diskPressure, total) + diskObs.note(),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "node-health",
				Affected:    affected,
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s describe node %s", cluster, strings.Join(affected, " ")),
				},
			})
		}
		if notReadyObs.seen() && notReady > 0 {
			affected := nodes.notReady()
			findings = append(findings, Finding{
				Rule:        "node-health/not-ready",
				Title:       fmt.Sprintf("%s has %d node(s) not ready", cluster, notReady),
				Description: fmt.Sprintf("%d of %d nodes are not reporting Ready=True. Workloads cannot be scheduled to these nodes.", notReady, total) + notReadyObs.note(),
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
		if slices.Contains(n.Conditions, condition) {
			out = append(out, n.Name)
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
	m, obs := clusterView(r, scannerName, cluster)
	if !obs.seen() {
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
				switch cv := c.(type) {
				case string:
					nv.Conditions = append(nv.Conditions, cv)
				case map[string]any:
					typ, _ := cv["type"].(string)
					status, _ := cv["status"].(string)
					if typ != "" && status == "True" {
						nv.Conditions = append(nv.Conditions, typ)
					}
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
		case capacityCritical:
			findings = append(findings, Finding{
				Rule:        "metrics/capacity-critical",
				Title:       fmt.Sprintf("%s is in critical state", ca.Cluster),
				Description: ca.Recommendation,
				Severity:    SeverityCritical,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		case capacityStrained:
			findings = append(findings, Finding{
				Rule:        "metrics/capacity-degraded",
				Title:       fmt.Sprintf("%s is degraded", ca.Cluster),
				Description: ca.Recommendation,
				Severity:    SeverityWarning,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		case capacityBusy:
			findings = append(findings, Finding{
				Rule:        "metrics/capacity-busy",
				Title:       fmt.Sprintf("%s is busy but healthy (CPU %.0f%%, memory %.0f%%)", ca.Cluster, ca.CPUUtilization, ca.MemoryUtilization),
				Description: ca.Recommendation,
				Severity:    SeverityInfo,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
			})
		}

		if ca.GroupDeviation != "" && !strings.HasPrefix(ca.GroupDeviation, "Within normal range") {
			findings = append(findings, Finding{
				Rule:        "metrics/group-deviation",
				Title:       fmt.Sprintf("%s deviates from group peers", ca.Cluster),
				Description: ca.GroupDeviation,
				Severity:    SeverityWarning,
				Cluster:     ca.Cluster,
				Scanner:     "metrics",
				Remediation: &Remediation{
					Command: fmt.Sprintf("# %s\nkubectl --context %s top nodes", strings.TrimSpace(ca.GroupDeviation), ca.Cluster),
				},
			})
		}
	}
	return findings
}

// quotaFindings reports clusters with no ResourceQuotas defined and ships a
// baseline manifest in the remediation block. Zero quotas is an absence claim, so it
// needs a completed quota run. The namespace count only shows namespaces exist, so a
// degraded namespace run is enough and marks the finding partial.
func quotaFindings(r *Report) []Finding {
	sec := r.Sections["resource-quotas"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		quotas, quotaObs := observeInt(r, "resource-quotas", cluster, "namespaces_with_quotas")
		nsCount, nsObs := observeInt(r, "namespaces", cluster, "count")
		if quotaObs == observed && nsObs.seen() && nsCount > 0 && quotas == 0 {
			findings = append(findings, Finding{
				Rule:        "resource-quotas/no-quota",
				Title:       fmt.Sprintf("%s has no resource quotas defined", cluster),
				Description: "No namespaces have ResourceQuota objects. There are no limits on resource consumption per namespace." + nsObs.note(),
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
// cluster trips at. Top reasons are included when the scanner provided them. An
// unobserved node count is not read as one node: the rate is left out and only the
// absolute thresholds apply.
func eventFindings(r *Report) []Finding {
	sec := r.Sections["events"]
	if sec == nil {
		return nil
	}
	var findings []Finding
	for _, cluster := range r.Clusters {
		warningCount, eventsObs := observeInt(r, "events", cluster, "warning_events")
		if !eventsObs.seen() || warningCount == 0 {
			continue
		}
		nodes, nodesObs := observeInt(r, "node-health", cluster, "node_count")
		perNode := 0.0
		if nodesObs.seen() {
			perNode = float64(warningCount) / float64(max(nodes, 1))
		}
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
		desc := fmt.Sprintf("%d warning events in the last hour. The node count was not observed, so no per-node rate.",
			warningCount)
		if nodesObs.seen() {
			desc = fmt.Sprintf("%d warning events in the last hour across %d node(s) (%.1f per node).",
				warningCount, max(nodes, 1), perNode)
		}
		if len(topReasons) > 0 {
			desc += " Top reasons: " + strings.Join(topReasons, ", ") + "."
		}
		desc += eventsObs.note()
		findings = append(findings, Finding{
			Rule:        "events/warning-volume",
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
	m, obs := clusterView(r, "events", cluster)
	if !obs.seen() {
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
		count, _ := util.Float64(entry["count"])
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
