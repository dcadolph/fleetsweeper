package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// systemNamespacePrefixes are the namespace name prefixes excluded from
// fleet-divergence findings. Cloud and add-on namespaces legitimately differ
// across providers; flagging them as drift drowns real signal.
var systemNamespacePrefixes = []string{
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

// systemNamespaceExact are the namespace names treated as system regardless
// of prefix matching.
var systemNamespaceExact = map[string]bool{
	"default":         true,
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// isSystemNamespace reports whether a namespace name should be treated as a
// system namespace and therefore excluded from divergence findings.
func isSystemNamespace(name string) bool {
	if systemNamespaceExact[name] {
		return true
	}
	for _, p := range systemNamespacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// versionFindings emits a single fleet-level finding when versions differ.
// Severity is calibrated to the Kubernetes version-skew policy: patch
// differences are info, single-minor skew is warning, larger skew is critical,
// so a routine rolling upgrade does not page.
func versionFindings(r *Report) []Finding {
	sec := r.Sections["version"]
	if sec == nil || sec.Uniform {
		return nil
	}
	versions := make(map[string]string, len(r.Clusters))
	uniqueVersions := make([]string, 0, len(r.Clusters))
	seen := make(map[string]bool)
	for _, cluster := range r.Clusters {
		v, obs := observeString(r, "version", cluster, "git_version")
		if !obs.seen() {
			continue
		}
		versions[cluster] = v
		if v != "" && !seen[v] {
			seen[v] = true
			uniqueVersions = append(uniqueVersions, v)
		}
	}
	if len(uniqueVersions) < 2 {
		return nil
	}

	severity := versionSkewSeverity(uniqueVersions)
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

	desc := fmt.Sprintf("Fleet runs %d distinct versions: %s.", len(uniqueVersions), strings.Join(uniqueVersions, ", "))
	majority, marks := versionMarks(r.Clusters, versions)
	if len(marks) > 0 {
		names := make([]string, 0, len(marks))
		for _, m := range marks {
			names = append(names, m.Cluster)
		}
		desc += fmt.Sprintf(" Off the majority version %s: %s.", majority, strings.Join(names, ", "))
	}

	return []Finding{{
		Rule:        "version/skew",
		Title:       "Kubernetes version skew across fleet",
		Description: desc,
		Severity:    severity,
		Cluster:     "fleet",
		Scanner:     "version",
		Affected:    affected,
		Marks:       marks,
		Remediation: &Remediation{
			Command: "kubectl version",
		},
	}}
}

// versionMarks returns the version most clusters run and a mark for each
// cluster whose skew from it is a minor version or more, at the severity that
// skew alone would carry. A tie for most common version names no majority,
// so it marks no cluster. Patch-only differences mark nothing.
func versionMarks(clusters []string, versions map[string]string) (string, []ClusterMark) {
	counts := make(map[string]int)
	for _, c := range clusters {
		if v := versions[c]; v != "" {
			counts[v]++
		}
	}
	majority, top, tied := "", 0, false
	for v, n := range counts {
		switch {
		case n > top:
			majority, top, tied = v, n, false
		case n == top:
			tied = true
		}
	}
	if tied || majority == "" {
		return "", nil
	}
	var marks []ClusterMark
	for _, c := range clusters {
		v := versions[c]
		if v == "" || v == majority {
			continue
		}
		if sev := versionSkewSeverity([]string{majority, v}); sev != SeverityInfo {
			marks = append(marks, ClusterMark{Cluster: c, Severity: sev})
		}
	}
	sort.Slice(marks, func(i, j int) bool { return marks[i].Cluster < marks[j].Cluster })
	return majority, marks
}

// namespaceFindings flags non-system namespace count divergence. System and
// cloud add-on namespaces are filtered through isSystemNamespace so legitimate
// per-cloud namespace differences do not become recurring warnings.
func namespaceFindings(r *Report) []Finding {
	sec := r.Sections["namespaces"]
	if sec == nil {
		return nil
	}
	counts := make(map[string]int, len(r.Clusters))
	for _, cluster := range r.Clusters {
		if n, obs := countNonSystemNamespaces(r, cluster); obs.seen() {
			counts[cluster] = n
		}
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
		Rule:        "namespaces/non-system-count-varies",
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
// the bare count when the scanner did not emit names. An unobserved cluster reports its
// observation so the caller can leave it out of the comparison.
func countNonSystemNamespaces(r *Report, cluster string) (int, observation) {
	m, obs := clusterView(r, "namespaces", cluster)
	if !obs.seen() {
		return 0, unobserved
	}
	if raw, ok := m["namespaces"].([]any); ok {
		count := 0
		for _, n := range raw {
			entry, ok := n.(map[string]any)
			if !ok {
				continue
			}
			name, _ := entry["name"].(string)
			if !isSystemNamespace(name) {
				count++
			}
		}
		return count, obs
	}
	count, ok := util.Float64(m["count"])
	if !ok {
		return 0, unobserved
	}
	return int(count), obs
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
		Rule:        "rbac/config-differs",
		Title:       "RBAC configuration differs across clusters",
		Description: "ClusterRoles, Roles, or their bindings differ between clusters. See the rbac-audit findings for named offenders.",
		Severity:    SeverityWarning,
		Cluster:     "fleet",
		Scanner:     "rbac",
	}}
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
		m, obs := clusterView(r, "deprecated-apis", cluster)
		if !obs.seen() {
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
			instances, _ := util.Float64(entry["instance_count"])
			instanceCount := int(instances)
			affected = append(affected, fmt.Sprintf("%s %s (%d instances, removed in %s)", apiVersion, kind, instanceCount, removedIn))
		}
		findings = append(findings, Finding{
			Rule:        "deprecated-apis/in-use",
			Title:       fmt.Sprintf("%s uses %d deprecated API version(s)", cluster, len(raw)),
			Description: "These API versions have been deprecated or removed in newer Kubernetes minor releases. Migrate before the next upgrade or workloads will fail." + obs.note(),
			Severity:    SeverityWarning,
			Cluster:     cluster,
			Scanner:     "deprecated-apis",
			Affected:    capList(affected),
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s get --raw /metrics 2>/dev/null | grep apiserver_requested_deprecated_apis", cluster),
			},
		})
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
		m, obs := clusterView(r, "cluster-info", cluster)
		if !obs.seen() {
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
			Rule:        "cluster-info/node-platform-drift",
			Title:       fmt.Sprintf("%s has node-level platform drift", cluster),
			Description: "Different nodes report different platform identities. Common cause: rolling node-pool replacement, stale AMI, or partially-completed upgrade." + obs.note(),
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
