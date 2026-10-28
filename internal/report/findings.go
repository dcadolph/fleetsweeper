package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
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
	// Rule names the check that produced this finding as scanner/slug, e.g.
	// "workload-security/privileged". It never carries a cluster name or a
	// count, so the same check on two clusters shares a rule.
	Rule string `json:"rule"`
	// Fingerprint is the stable identifier of this finding, a hash of its
	// cluster, scanner, and rule. Acknowledgements and persistence key on it.
	Fingerprint string `json:"fingerprint"`
	// Acked reports whether an active acknowledgement covers this finding.
	// Only the server, which holds the acknowledgements, sets it.
	Acked bool `json:"acked"`
	// Affected lists the offending resources (nodes, pods, bindings, images)
	// scoped to this finding. Empty when the finding has no specific noun.
	Affected []string `json:"affected,omitempty"`
	// Remediation is the suggested fix. Empty when no automated suggestion fits.
	Remediation *Remediation `json:"remediation,omitempty"`
	// Norm is the fleet or cohort norm a fleet-relative finding was measured
	// against. An absolute-rule finding carries one only when it absorbed the
	// norm finding on the field it counts, and is nil otherwise.
	Norm *NormBasis `json:"norm,omitempty"`
	// Marks names the clusters a fleet-scoped finding holds responsible, each
	// with the severity it sets on that cluster's status. Empty on cluster
	// findings and on fleet findings no single cluster is behind.
	Marks []ClusterMark `json:"marks,omitempty"`
}

// ClusterMark ties a fleet-scoped finding to one cluster it implicates.
type ClusterMark struct {
	// Cluster is the implicated cluster.
	Cluster string `json:"cluster"`
	// Severity is the severity the finding sets on this cluster's status.
	Severity string `json:"severity"`
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
	// DegradedScanners is how many scanner runs did not return complete,
	// trustworthy data for this cluster (errored, degraded, or unavailable).
	// Nonzero means this cluster's report rests on partial coverage.
	DegradedScanners int `json:"degraded_scanners,omitempty"`
}

// pairwiseFleetLimit is the largest fleet that keeps the fleet-wide version,
// namespace, and RBAC drift findings alongside outlier findings. Above it a
// fleet-wide finding lists too many clusters to act on, so outlier findings,
// which name the deviant, replace it.
const pairwiseFleetLimit = 20

// generateFindings analyzes a report and produces human-readable findings.
// Above pairwiseFleetLimit clusters, outlier findings replace the fleet-wide
// version, namespace, and RBAC drift findings when any outlier exists.
func generateFindings(r *Report) []Finding {
	var findings []Finding

	findings = append(findings, outlierFindings(r)...)
	if len(r.Outliers) == 0 || len(r.Clusters) <= pairwiseFleetLimit {
		findings = append(findings, versionFindings(r)...)
		findings = append(findings, namespaceFindings(r)...)
		findings = append(findings, rbacFindings(r)...)
	}
	findings = append(findings, cohortOutlierFindings(r)...)

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
	findings = append(findings, vulnerabilityFindings(r)...)
	findings = append(findings, deprecatedAPIFindings(r)...)
	findings = append(findings, coverageFindings(r)...)
	findings = append(findings, admissionFindings(r)...)
	findings = append(findings, clusterInfoFindings(r)...)
	findings = append(findings, compositeBadDeployFindings(r)...)
	findings = dropRedundant(findings, scopeMembers(r))

	sortFindings(findings)

	return stampFingerprints(findings)
}

// sortFindings orders findings most severe first, keeping the relative order of equals.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return util.SeverityRank(fs[i].Severity) > util.SeverityRank(fs[j].Severity)
	})
}

// clusterRule keys a finding by its cluster and rule.
type clusterRule struct {
	// Cluster is the finding's cluster.
	Cluster string
	// Rule is the finding's rule.
	Rule string
}

// clusterField keys a norm finding by its cluster and the field its norm describes.
type clusterField struct {
	// Cluster is the finding's cluster.
	Cluster string
	// Field is the scanner field the norm describes.
	Field FieldRef
}

// scopedField keys a norm finding by its cluster, the field its norm describes, and the scope
// the norm was computed over.
type scopedField struct {
	// Cluster is the finding's cluster.
	Cluster string
	// Field is the scanner field the norm describes.
	Field FieldRef
	// Scope is the norm's scope, "fleet" or a cohort name.
	Scope string
}

// scopeMembers lists the clusters each norm scope was computed over: the fleet under
// NormScopeFleet and every cohort under its name.
func scopeMembers(r *Report) map[string][]string {
	members := map[string][]string{NormScopeFleet: r.Clusters}
	for _, c := range r.Cohorts {
		members[c.Name] = c.Clusters
	}
	return members
}

// dropRedundant removes a norm finding whose fact another finding on the same cluster already
// states at an equal or higher severity, so one fact is counted once. A norm finding on a field
// is dropped when the absolute rule that counts the field fired on the cluster and singles it
// out: within the norm's scope the rule fired on no cluster that holds the norm, so "the rule
// fired" and "off the norm" name the same clusters. The absolute finding takes the norm when it
// has none. A rule that fires on norm clusters too, such as a namespace-without-policy count on
// a fleet where every cluster has one, states a fact the fleet shares, not the deviation, and
// drops nothing. A norm finding is also dropped when a field it restates (its RedundantWith) is
// stated by a norm finding or by a singling absolute rule counting that field. When the restated
// field's only statement is a norm finding of lower severity, that finding is dropped instead.
// members lists the clusters of each scope, from scopeMembers. Every judgment reads the
// original list, so the order of the findings does not matter.
func dropRedundant(findings []Finding, members map[string][]string) []Finding {
	absolute := make(map[clusterRule]int)
	firedOn := make(map[string][]string)
	norm := make(map[clusterField]int)
	normIn := make(map[scopedField]bool)
	isNorm := make([]bool, len(findings))
	for i, f := range findings {
		isNorm[i] = f.Norm != nil
		if !isNorm[i] {
			key := clusterRule{f.Cluster, f.Rule}
			if _, ok := absolute[key]; !ok {
				absolute[key] = i
				firedOn[f.Rule] = append(firedOn[f.Rule], f.Cluster)
			}
			continue
		}
		field := ref(f.Scanner, f.Norm.Field)
		norm[clusterField{f.Cluster, field}] = i
		normIn[scopedField{f.Cluster, field, f.Norm.Scope}] = true
	}
	singles := func(rule string, field FieldRef, scope string) bool {
		population, ok := members[scope]
		if !ok {
			return false
		}
		for _, cluster := range firedOn[rule] {
			if !slices.Contains(population, cluster) {
				continue
			}
			if !normIn[scopedField{cluster, field, scope}] {
				return false
			}
		}
		return true
	}
	counting := func(cluster string, field FieldRef, scope string) (int, bool) {
		spec, ok := lookupField(field.Scanner, field.Field)
		if !ok || spec.CountedBy == "" {
			return 0, false
		}
		j, ok := absolute[clusterRule{cluster, spec.CountedBy}]
		if !ok || !singles(spec.CountedBy, field, scope) {
			return 0, false
		}
		return j, true
	}

	drop := make([]bool, len(findings))
	for i, f := range findings {
		if !isNorm[i] {
			continue
		}
		j, ok := counting(f.Cluster, ref(f.Scanner, f.Norm.Field), f.Norm.Scope)
		if !ok || util.SeverityRank(findings[j].Severity) < util.SeverityRank(f.Severity) {
			continue
		}
		drop[i] = true
		if findings[j].Norm == nil {
			findings[j].Norm = f.Norm
			findings[j].Description = strings.TrimSpace(
				findings[j].Description + " " + normSentence(f.Cluster, f.Norm))
		}
	}
	for i, f := range findings {
		if !isNorm[i] || drop[i] {
			continue
		}
		spec, _ := lookupField(f.Scanner, f.Norm.Field)
		rank := util.SeverityRank(f.Severity)
		for _, target := range spec.RedundantWith {
			if j, ok := counting(f.Cluster, target, f.Norm.Scope); ok &&
				util.SeverityRank(findings[j].Severity) >= rank {
				drop[i] = true
				break
			}
			j, ok := norm[clusterField{f.Cluster, target}]
			if !ok {
				continue
			}
			if util.SeverityRank(findings[j].Severity) >= rank {
				drop[i] = true
				break
			}
			if _, counted := counting(f.Cluster, target, f.Norm.Scope); !counted {
				drop[j] = true
			}
		}
	}

	kept := findings[:0]
	for i, f := range findings {
		if !drop[i] {
			kept = append(kept, f)
		}
	}
	return kept
}

// normSentence states the norm n of a finding on cluster as a sentence, e.g.
// "memory_pressure_nodes is 2 on prod-1, where every other cluster in the fleet reports
// exactly 0."
func normSentence(cluster string, n *NormBasis) string {
	scope := scopeNoun(n.Scope)
	switch {
	case n.Kind == NormKindNumeric && n.Exact:
		return fmt.Sprintf("%s is %s on %s, where %s.", n.Field, n.Value, cluster,
			exactNormPhrase(n.ModeShare, n.SampleSize, formatNum(n.Median), scope))
	case n.Kind == NormKindNumeric:
		return fmt.Sprintf("%s is %s on %s, against a median of %s across %d clusters in %s.",
			n.Field, n.Value, cluster, formatNum(n.Median), n.SampleSize, scope)
	case n.Kind == NormKindString:
		return fmt.Sprintf("%s is %q on %s, against %q held by %.0f%% of %s.",
			n.Field, n.Value, cluster, n.Mode, n.ModeShare*100, scope)
	case n.Kind == NormKindSet:
		return fmt.Sprintf("%s on %s lacks %d of the %d members %s holds in common.",
			n.Field, cluster, len(n.Missing), len(n.Consensus), scope)
	}
	return ""
}

// outlierFindings converts OutlierResults into human-readable findings, each
// with a remediation that states the gap to the fleet norm.
func outlierFindings(r *Report) []Finding {
	findings := make([]Finding, 0, len(r.Outliers))
	for _, o := range r.Outliers {
		if o.ExplainedBy != "" {
			continue
		}
		findings = append(findings, Finding{
			Rule:  outlierRule(o.Scanner, o.Field, false),
			Title: outlierTitle(o, "the fleet norm", "fleet norm"),
			Description: fmt.Sprintf("%s reports %s=%s while the fleet norm is %s (scanner: %s).%s",
				o.Cluster, o.Field, o.Value, o.FleetNorm, scannerLabels[o.Scanner], favorableNote(o)),
			Severity:    o.Severity,
			Cluster:     o.Cluster,
			Scanner:     o.Scanner,
			Affected:    []string{o.Field},
			Remediation: normRemediation(o, NormScopeFleet),
			Norm:        o.Basis(),
		})
	}
	return findings
}

// cohortOutlierFindings converts within-cohort outliers into findings so drift
// that is invisible at fleet scale still reaches the fleet score, the ranked
// recommendations, and alerts. Outliers already reported against the whole
// fleet are skipped so a cluster is not flagged twice for the same field.
func cohortOutlierFindings(r *Report) []Finding {
	if len(r.Cohorts) == 0 {
		return nil
	}
	fleet := make(map[string]struct{}, len(r.Outliers))
	for _, o := range r.Outliers {
		fleet[outlierKey(o.Cluster, o.Field, o.Scanner)] = struct{}{}
	}
	var findings []Finding
	for _, c := range r.Cohorts {
		for _, o := range c.Outliers {
			if _, dup := fleet[outlierKey(o.Cluster, o.Field, o.Scanner)]; dup {
				continue
			}
			findings = append(findings, Finding{
				Rule:  outlierRule(o.Scanner, o.Field, true),
				Title: outlierTitle(o, "its cohort norm", "its cohort"),
				Description: fmt.Sprintf(
					"Within cohort %q, %s reports %s=%s while the cohort norm is %s (scanner: %s).%s",
					c.Name, o.Cluster, o.Field, o.Value, o.FleetNorm, scannerLabels[o.Scanner],
					favorableNote(o),
				),
				Severity:    o.Severity,
				Cluster:     o.Cluster,
				Scanner:     o.Scanner,
				Affected:    []string{o.Field},
				Remediation: normRemediation(o, fmt.Sprintf("cohort %q", c.Name)),
				Norm:        o.Basis(),
			})
		}
	}
	return findings
}

// outlierTitle titles an outlier finding: "better than <better>" for a favorable outlier and
// "deviates from <norm>" otherwise.
func outlierTitle(o OutlierResult, better, norm string) string {
	if o.Favorable {
		return fmt.Sprintf("%s is better than %s on %s", o.Cluster, better, o.Field)
	}
	return fmt.Sprintf("%s deviates from %s on %s", o.Cluster, norm, o.Field)
}

// favorableNote explains a favorable outlier's info severity, or returns "" for any other.
func favorableNote(o OutlierResult) string {
	if !o.Favorable {
		return ""
	}
	better := "Lower"
	if spec, _ := lookupField(o.Scanner, o.Field); spec.Polarity == DownIsBad {
		better = "Higher"
	}
	return fmt.Sprintf(" %s is better for this field, so this is not a regression. If the cluster"+
		" differs by design, tag it into a cohort.", better)
}

// outlierKey identifies an outlier by cluster, field, and scanner so fleet and
// cohort findings for the same deviation can be deduplicated.
func outlierKey(cluster, field, scanner string) string {
	return cluster + "\x00" + field + "\x00" + scanner
}

// generateClusterHealth builds per-cluster health summaries. A cluster's
// status and counts come from its own findings and from fleet-scoped findings
// that mark it: a fleet finding such as version skew is the fleet's, scored
// once through its own term, and sets status only on the clusters it names.
func generateClusterHealth(r *Report, findings []Finding) []ClusterHealth {
	healths := make([]ClusterHealth, 0, len(r.Clusters))
	degradedByCluster := r.DegradedByCluster()
	for _, cluster := range r.Clusters {
		h := ClusterHealth{
			Name:          cluster,
			Status:        "healthy",
			FindingCounts: clusterSeverityCounts(cluster, findings),
		}
		if h.FindingCounts[SeverityCritical] > 0 {
			h.Status = "critical"
		} else if h.FindingCounts[SeverityWarning] > 0 {
			h.Status = "degraded"
		}

		h.KubernetesVersion = getStringField(r, "version", cluster, "git_version")
		h.NodeCount = getIntField(r, "node-health", cluster, "node_count")
		h.HealthyNodes = getIntField(r, "node-health", cluster, "healthy_nodes")
		h.AvgCPU = getMetricsFloat(r, cluster, "avg_cpu_percent")
		h.AvgMemory = getMetricsFloat(r, cluster, "avg_memory_percent")
		h.WarningEvents = getIntField(r, "events", cluster, "warning_events")
		h.NamespaceCount = getIntField(r, "namespaces", cluster, "count")
		h.DegradedScanners = degradedByCluster[cluster]

		healths = append(healths, h)
	}
	return healths
}

// capList returns the slice capped at maxAffected items with an "and N more" suffix when
// truncated. Used to keep finding output readable on wide fleets.
func capList(items []string) []string {
	if len(items) <= maxAffected {
		return items
	}
	out := make([]string, 0, maxAffected+1)
	out = append(out, items[:maxAffected]...)
	out = append(out, fmt.Sprintf("...and %d more", len(items)-maxAffected))
	return out
}

// clusterData returns a cluster's scanner payload as a generic map, or nil when the section,
// cluster, or a valid conversion is absent. The map may be the report's own, so callers must not
// modify it.
func clusterData(r *Report, scannerName, cluster string) map[string]any {
	sec := r.Sections[scannerName]
	if sec == nil {
		return nil
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil
	}
	m, _ := genericMap(data)
	return m
}

// getStringField extracts a string field from a cluster's scanner data.
func getStringField(r *Report, scannerName, cluster, field string) string {
	s, _ := clusterData(r, scannerName, cluster)[field].(string)
	return s
}

// getIntField extracts an integer field from a cluster's scanner data.
func getIntField(r *Report, scannerName, cluster, field string) int {
	n, _ := util.Float64(clusterData(r, scannerName, cluster)[field])
	return int(n)
}

// getMetricsFloat extracts a float field from a cluster's metrics scanner data.
func getMetricsFloat(r *Report, cluster, field string) float64 {
	n, _ := util.Float64(clusterData(r, "metrics", cluster)[field])
	return n
}
