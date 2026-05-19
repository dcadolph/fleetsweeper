// Package explain provides operator-facing explanations for Fleetsweeper
// findings and scanners. Keys map to rich descriptions covering what a
// finding means, how Fleetsweeper computes its severity, suggested
// investigation paths, and related signals. The `fleetsweeper why`
// subcommand reads from this map.
//
// Adding a new entry is intentionally lightweight: append a Topic literal
// to topics() and the CLI surfaces it automatically.
package explain

import (
	"fmt"
	"sort"
	"strings"
)

// Topic is the explainer entry for one scanner, finding family, or concept.
type Topic struct {
	// Key is the lookup token, e.g. "node-health", "version-skew", "fleet-score".
	Key string
	// Aliases are additional tokens that resolve to this entry.
	Aliases []string
	// Title is the human-readable heading.
	Title string
	// Summary is a single-paragraph plain-English explanation.
	Summary string
	// Severity describes how Fleetsweeper assigns critical/warning/info.
	Severity string
	// HowComputed describes the data path that produces the finding.
	HowComputed string
	// Remediation lists the recommended fixes, in priority order.
	Remediation []string
	// Probes lists kubectl-or-similar commands to investigate locally.
	Probes []string
	// Related lists other topic keys an operator may want to read next.
	Related []string
}

// topics is the authoritative list of explainer entries. Append to extend.
// Sorted alphabetically by Key here purely for source-file legibility; the
// runtime sort happens in Keys().
func topics() []Topic {
	return []Topic{
		{
			Key:     "fleet-score",
			Aliases: []string{"score"},
			Title:   "Fleet Score",
			Summary: "A single 0-100 indicator of overall fleet health. Lower is worse. " +
				"Designed for a status TV: glance at the number, drill in if it moves.",
			Severity: "The score itself is not a finding. Operators usually treat <70 as " +
				"page-worthy, 70-85 as triage soon, and 85+ as healthy.",
			HowComputed: "Start at 100. Subtract for findings (capped per severity to " +
				"prevent noisy fleets from collapsing), per-cluster health distribution, " +
				"Kubernetes version skew, and the worst cluster's unhealthy-node fraction. " +
				"See internal/report/score.go for the exact weights.",
			Remediation: []string{
				"Click the score on the dashboard for the Drivers list, which names the top three factors pulling it down.",
				"Open the per-cluster forecast panel to see which clusters are most likely to drag the score down further.",
			},
			Probes: []string{
				"curl -s localhost:8080/api/scans/$(curl -s localhost:8080/api/scans?limit=1 | jq -r '.[0].id')/report | jq '.fleet_score'",
			},
			Related: []string{"cluster-health", "version-skew", "outliers"},
		},
		{
			Key:     "node-health",
			Aliases: []string{"nodes", "memory-pressure", "not-ready"},
			Title:   "Node Health",
			Summary: "Per-cluster node condition data: Ready, MemoryPressure, DiskPressure, " +
				"PIDPressure. Surfaces nodes the scheduler will avoid or that risk OOM.",
			Severity: "MemoryPressure and NotReady map to critical; DiskPressure and " +
				"PIDPressure to warning; an unhealthy fraction above 20% escalates.",
			HowComputed: "Reads .status.conditions from every node, aggregates per-cluster, " +
				"then emits per-condition counts and per-cluster ratios.",
			Remediation: []string{
				"kubectl --context <ctx> describe node <name> on the listed nodes.",
				"Check eviction events with kubectl get events --field-selector reason=Evicted.",
				"If memory pressure is persistent, add capacity or right-size workloads.",
			},
			Probes: []string{
				"kubectl --context <ctx> get nodes -o wide",
				"kubectl --context <ctx> top nodes",
			},
			Related: []string{"metrics", "capacity"},
		},
		{
			Key:     "version-skew",
			Aliases: []string{"version", "kubernetes-version"},
			Title:   "Kubernetes Version Skew",
			Summary: "Divergence in the Kubernetes API server version across the fleet.",
			Severity: "Patch differences are info, single-minor skew is warning, " +
				"skew exceeding one minor (outside the upstream skew policy) is critical.",
			HowComputed: "Reads version.git_version from every cluster's discovery API, " +
				"parses major.minor.patch, and compares min-vs-max minor across the fleet.",
			Remediation: []string{
				"Schedule the lagging cluster's control plane upgrade.",
				"For managed services, check the cloud provider's release cadence and " +
					"auto-upgrade settings.",
			},
			Probes: []string{
				"kubectl --context <ctx> version --short",
			},
			Related: []string{"deprecated-apis", "fleet-score"},
		},
		{
			Key:     "outliers",
			Aliases: []string{"mad", "outlier-detection"},
			Title:   "Outlier Detection (MAD)",
			Summary: "Statistical detection of clusters that deviate from the fleet's own " +
				"baseline. Activates when the fleet has more than 20 clusters and each " +
				"data point has 8+ reporting values.",
			Severity: "Outlier severity inherits from the underlying field. The deviation " +
				"score (modified z-score) is included so operators can rank.",
			HowComputed: "Median + median absolute deviation per numeric field, with " +
				"mode-mass voting for strings. Sample-size and MAD-zero gates suppress " +
				"false positives on near-uniform data.",
			Remediation: []string{
				"Investigate the cluster's local configuration drift.",
				"Tune sensitivity with --outlier-threshold (lower flags more outliers).",
			},
			Related: []string{"trends", "fleet-score"},
		},
		{
			Key:     "trends",
			Aliases: []string{"trend", "regression", "forecast"},
			Title:   "Trends and Forecasts",
			Summary: "OLS linear regression over time on tracked metrics, with R² and " +
				"slope t-statistic gating so noise does not flip the arrow.",
			Severity: "Trend findings inherit severity from the underlying metric. " +
				"Forecasts on Fleet Score are surfaced as projections, not findings.",
			HowComputed: "Per-field least-squares fit; need at least five points to " +
				"report non-stable directions; t-stat ≥ 2 required for high confidence.",
			Remediation: []string{
				"Use trends to plan capacity ahead of pressure rather than reacting.",
				"Watch the cluster forecast panel on the dashboard for clusters " +
					"projected to degrade.",
			},
			Related: []string{"fleet-score", "capacity"},
		},
		{
			Key:     "image-audit",
			Aliases: []string{"images", "latest-tag", "digest"},
			Title:   "Image Hygiene",
			Summary: "Detects :latest tags, missing digest pins, and pull-policy combinations " +
				"that make deployments non-reproducible.",
			Severity: "Critical when a production cluster is detected pulling :latest. " +
				"Warning for missing digests in staging. Info for dev clusters.",
			HowComputed: "Walks every container spec in every workload, parses image " +
				"references, and flags strings without a sha256 digest or with the :latest tag.",
			Remediation: []string{
				"Repin manifests to immutable digests: image: foo@sha256:...",
				"Add an admission policy that rejects :latest at submit time.",
			},
			Related: []string{"workload-security", "rbac-audit"},
		},
		{
			Key:     "network-policies",
			Aliases: []string{"netpol", "default-deny"},
			Title:   "Network Policies",
			Summary: "Coverage of NetworkPolicy resources across namespaces. Surfaces " +
				"namespaces with no policies (everything allowed).",
			Severity: "Critical for production namespaces with no policies; warning for " +
				"system-adjacent namespaces; info for dev.",
			HowComputed: "Lists NetworkPolicy resources per namespace and joins against " +
				"the namespace list; namespaces with zero policies are flagged.",
			Remediation: []string{
				"Apply a default-deny NetworkPolicy to non-system namespaces; allow " +
					"explicit ingress/egress from there.",
				"The dashboard includes a paste-ready YAML manifest in the finding.",
			},
			Probes: []string{
				"kubectl --context <ctx> -n <ns> get networkpolicy",
			},
			Related: []string{"workload-security", "security"},
		},
		{
			Key:     "workload-security",
			Aliases: []string{"privileged", "host-namespace", "seccomp"},
			Title:   "Workload Security",
			Summary: "Privileged containers, host namespaces, capability additions, " +
				"seccomp profiles, and hostPath mounts across all pods.",
			Severity: "Critical for privileged containers and hostPID/hostNetwork outside " +
				"system namespaces; warning for capability additions and missing seccomp; " +
				"info for run-as-root in dev.",
			HowComputed: "Reads .spec.securityContext at both pod and container level, " +
				"correlates with workload namespace and labels to filter system workloads.",
			Remediation: []string{
				"Drop privileged: true unless the workload genuinely needs full host access.",
				"Add seccompProfile: { type: RuntimeDefault } as a baseline.",
				"Move legitimately-privileged workloads into a dedicated namespace with " +
					"Pod Security enforce=privileged for clarity.",
			},
			Related: []string{"security", "rbac-audit"},
		},
		{
			Key:     "rbac-audit",
			Aliases: []string{"rbac", "cluster-admin", "wildcard-rules"},
			Title:   "RBAC Audit",
			Summary: "Cluster-admin bindings, wildcard rules, and default-ServiceAccount " +
				"bindings — the three classes that frequently lead to unintended " +
				"privilege escalation.",
			Severity: "Critical for cluster-admin granted to default SAs or wildcard " +
				"resource+verb rules outside kube-system; warning for any non-system " +
				"cluster-admin binding.",
			HowComputed: "Walks ClusterRoleBindings and RoleBindings, joins with the " +
				"referenced ClusterRoles, and filters out system bindings via prefix lists.",
			Remediation: []string{
				"Replace cluster-admin grants with least-privilege ClusterRoles scoped " +
					"to the actual resources the workload touches.",
				"Audit any binding to system:serviceaccount:default:*.",
			},
			Related: []string{"workload-security", "security"},
		},
		{
			Key:     "security",
			Aliases: []string{"pss", "pod-security-standards"},
			Title:   "Pod Security Standards",
			Summary: "Enforcement state of Pod Security admission labels across namespaces.",
			Severity: "Critical when production namespaces have no PSS enforce label; " +
				"warning for missing audit/warn levels.",
			HowComputed: "Reads pod-security.kubernetes.io/enforce labels on every " +
				"namespace; system namespaces are excluded.",
			Remediation: []string{
				"kubectl label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite",
				"For higher security, use restricted instead of baseline.",
			},
			Related: []string{"workload-security", "network-policies"},
		},
	}
}

// indexByKey returns a lookup map from key/alias to topic, lowercase
// normalized.
func indexByKey() map[string]Topic {
	out := map[string]Topic{}
	for _, t := range topics() {
		out[strings.ToLower(t.Key)] = t
		for _, a := range t.Aliases {
			out[strings.ToLower(a)] = t
		}
	}
	return out
}

// Lookup returns the topic matching key (case-insensitive), or nil. Falls
// back to substring matching against titles when the exact key is not found,
// so misspellings or shortened forms still hit.
func Lookup(key string) *Topic {
	idx := indexByKey()
	if t, ok := idx[strings.ToLower(key)]; ok {
		return &t
	}
	needle := strings.ToLower(key)
	for _, t := range topics() {
		if strings.Contains(strings.ToLower(t.Title), needle) ||
			strings.Contains(strings.ToLower(t.Summary), needle) {
			return &t
		}
	}
	return nil
}

// Keys returns every key in alphabetical order.
func Keys() []string {
	ts := topics()
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Key)
	}
	sort.Strings(out)
	return out
}

// Render returns a plain-text explainer for the topic. When color is true,
// section headings get ANSI dim/bright codes for terminal readability.
func Render(t Topic, color bool) string {
	dim := func(s string) string {
		if !color {
			return s
		}
		return "\033[90m" + s + "\033[0m"
	}
	bright := func(s string) string {
		if !color {
			return s
		}
		return "\033[1m" + s + "\033[0m"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", bright(t.Title))
	fmt.Fprintf(&b, "%s  %s\n\n", dim("Summary:"), t.Summary)
	if t.Severity != "" {
		fmt.Fprintf(&b, "%s  %s\n\n", dim("Severity:"), t.Severity)
	}
	if t.HowComputed != "" {
		fmt.Fprintf(&b, "%s  %s\n\n", dim("How computed:"), t.HowComputed)
	}
	if len(t.Remediation) > 0 {
		fmt.Fprintf(&b, "%s\n", dim("Remediation:"))
		for _, r := range t.Remediation {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
		fmt.Fprintln(&b)
	}
	if len(t.Probes) > 0 {
		fmt.Fprintf(&b, "%s\n", dim("Probes:"))
		for _, p := range t.Probes {
			fmt.Fprintf(&b, "  $ %s\n", p)
		}
		fmt.Fprintln(&b)
	}
	if len(t.Related) > 0 {
		fmt.Fprintf(&b, "%s  %s\n", dim("Related:"), strings.Join(t.Related, ", "))
	}
	return b.String()
}
