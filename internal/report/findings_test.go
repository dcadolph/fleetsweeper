package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// testReport builds a report whose sections hold the given per-cluster
// payloads, keyed by scanner then cluster. Clusters are the sorted union of
// every payload's cluster. Sections are non-uniform so fleet-level generators
// run.
func testReport(sections map[string]map[string]any) *Report {
	seen := map[string]bool{}
	r := &Report{Sections: map[string]*SectionReport{}}
	for name, perCluster := range sections {
		r.Sections[name] = &SectionReport{PerCluster: perCluster}
		for c := range perCluster {
			if !seen[c] {
				seen[c] = true
				r.Clusters = append(r.Clusters, c)
			}
		}
	}
	sort.Strings(r.Clusters)
	return r
}

// generatorCase is one table row for TestFindingGenerators.
type generatorCase struct {
	// Name labels the case.
	Name string
	// Generate is the generator under test.
	Generate func(*Report) []Finding
	// Report is the input report.
	Report *Report
	// WantResult is the exact findings the generator must return.
	WantResult []Finding
}

// privilegedCommand is the workload-security privileged remediation for
// cluster a.
const privilegedCommand = `kubectl --context a get pods -A -o json | jq -r '.items[] | ` +
	`select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + "/" + .metadata.name'`

// TestFindingGenerators feeds each generator a scanner payload and checks the
// exact findings, rule included.
func TestFindingGenerators(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	tests := []generatorCase{{ // Test 0: Node pressure and not-ready nodes are named.
		Name:     "node health",
		Generate: nodeHealthFindings,
		Report: testReport(map[string]map[string]any{"node-health": {"a": map[string]any{
			"node_count": 3, "memory_pressure_nodes": 1, "disk_pressure_nodes": 1, "not_ready_nodes": 1,
			"nodes": []any{
				map[string]any{"name": "n1", "ready": true, "conditions": []any{"MemoryPressure"}},
				map[string]any{"name": "n2", "ready": false, "conditions": []any{"DiskPressure"}},
				map[string]any{"name": "n3", "ready": true},
			},
		}}}),
		WantResult: []Finding{{
			Rule: "node-health/memory-pressure", Title: "a has 1 node(s) under memory pressure",
			Description: "1 of 3 nodes report MemoryPressure=True. Pods on these nodes risk OOM kills and the scheduler will avoid them.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "node-health", Affected: []string{"n1"},
			Remediation: &Remediation{Command: "kubectl --context a describe node n1"},
		}, {
			Rule: "node-health/disk-pressure", Title: "a has 1 node(s) under disk pressure",
			Description: "1 of 3 nodes report DiskPressure=True. Pods may be evicted to free disk space.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "node-health", Affected: []string{"n2"},
			Remediation: &Remediation{Command: "kubectl --context a describe node n2"},
		}, {
			Rule: "node-health/not-ready", Title: "a has 1 node(s) not ready",
			Description: "1 of 3 nodes are not reporting Ready=True. Workloads cannot be scheduled to these nodes.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "node-health", Affected: []string{"n2"},
			Remediation: &Remediation{Command: "kubectl --context a describe node n2"},
		}},
	}, { // Test 1: Healthy nodes yield nothing.
		Name:       "node health clean",
		Generate:   nodeHealthFindings,
		Report:     testReport(map[string]map[string]any{"node-health": {"a": map[string]any{"node_count": 3}}}),
		WantResult: nil,
	}, { // Test 2: More than half unenforced is critical.
		Name:     "psa critical",
		Generate: securityFindings,
		Report: testReport(map[string]map[string]any{"security": {"a": map[string]any{
			"unenforced_count": 6, "namespace_count": 10,
		}}}),
		WantResult: []Finding{{
			Rule: "security/psa-unenforced", Title: "a has 6 namespace(s) without Pod Security enforcement",
			Description: "6 of 10 namespaces (60%) have no Pod Security Standards enforce label. Pods in these namespaces can run with any privileges.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "security",
			Remediation: &Remediation{Command: "kubectl --context a label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite"},
		}},
	}, { // Test 3: Exactly half unenforced stays a warning.
		Name:     "psa half",
		Generate: securityFindings,
		Report: testReport(map[string]map[string]any{"security": {"a": map[string]any{
			"unenforced_count": 5, "namespace_count": 10,
		}}}),
		WantResult: []Finding{{
			Rule: "security/psa-unenforced", Title: "a has 5 namespace(s) without Pod Security enforcement",
			Description: "5 of 10 namespaces (50%) have no Pod Security Standards enforce label. Pods in these namespaces can run with any privileges.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "security",
			Remediation: &Remediation{Command: "kubectl --context a label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite"},
		}},
	}, { // Test 4: A missing namespace total never reports a share over 100%.
		Name:     "psa no total",
		Generate: securityFindings,
		Report: testReport(map[string]map[string]any{"security": {"a": map[string]any{
			"unenforced_count": 4,
		}}}),
		WantResult: []Finding{{
			Rule: "security/psa-unenforced", Title: "a has 4 namespace(s) without Pod Security enforcement",
			Description: "4 namespaces have no Pod Security Standards enforce label. Pods in these namespaces can run with any privileges.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "security",
			Remediation: &Remediation{Command: "kubectl --context a label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite"},
		}},
	}, { // Test 5: Namespaces without policies get the default-deny manifest.
		Name:     "network policies",
		Generate: networkFindings,
		Report: testReport(map[string]map[string]any{"network-policies": {"a": map[string]any{
			"namespaces_without_policies": 2,
		}}}),
		WantResult: []Finding{{
			Rule: "network-policies/no-policy", Title: "a has 2 namespace(s) with no network policies",
			Description: "2 namespaces have no NetworkPolicy resources. All pod-to-pod traffic is allowed in these namespaces.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "network-policies",
			Remediation: &Remediation{YAML: defaultDenyNetworkPolicyYAML},
		}},
	}, { // Test 6: No quotas with namespaces present gets the quota manifest.
		Name:     "quotas",
		Generate: quotaFindings,
		Report: testReport(map[string]map[string]any{
			"resource-quotas": {"a": map[string]any{"namespaces_with_quotas": 0}},
			"namespaces":      {"a": map[string]any{"count": 4}},
		}),
		WantResult: []Finding{{
			Rule: "resource-quotas/no-quota", Title: "a has no resource quotas defined",
			Description: "No namespaces have ResourceQuota objects. There are no limits on resource consumption per namespace.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "resource-quotas",
			Remediation: &Remediation{YAML: defaultResourceQuotaYAML},
		}},
	}, { // Test 7: Fifteen warnings per node is a warning with top reasons named.
		Name:     "events per node",
		Generate: eventFindings,
		Report: testReport(map[string]map[string]any{
			"events": {"a": map[string]any{
				"warning_events":      30,
				"top_warning_reasons": []any{map[string]any{"reason": "BackOff", "count": 20}},
			}},
			"node-health": {"a": map[string]any{"node_count": 2}},
		}),
		WantResult: []Finding{{
			Rule: "events/warning-volume", Title: "a has 30 warning event(s) in the last hour",
			Description: "30 warning events in the last hour across 2 node(s) (15.0 per node). Top reasons: BackOff (20).",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "events", Affected: []string{"BackOff (20)"},
			Remediation: &Remediation{Command: "kubectl --context a get events --field-selector type=Warning --sort-by=.lastTimestamp -A | tail -50"},
		}},
	}, { // Test 8: Exactly five per node and at most 200 total stays info.
		Name:     "events boundary",
		Generate: eventFindings,
		Report: testReport(map[string]map[string]any{
			"events":      {"a": map[string]any{"warning_events": 10}},
			"node-health": {"a": map[string]any{"node_count": 2}},
		}),
		WantResult: []Finding{{
			Rule: "events/warning-volume", Title: "a has 10 warning event(s) in the last hour",
			Description: "10 warning events in the last hour across 2 node(s) (5.0 per node).",
			Severity:    SeverityInfo, Cluster: "a", Scanner: "events",
			Remediation: &Remediation{Command: "kubectl --context a get events --field-selector type=Warning --sort-by=.lastTimestamp -A | tail -50"},
		}},
	}, { // Test 9: Over a thousand warnings is critical regardless of node count.
		Name:     "events critical",
		Generate: eventFindings,
		Report: testReport(map[string]map[string]any{
			"events":      {"a": map[string]any{"warning_events": 1001}},
			"node-health": {"a": map[string]any{"node_count": 1000}},
		}),
		WantResult: []Finding{{
			Rule: "events/warning-volume", Title: "a has 1001 warning event(s) in the last hour",
			Description: "1001 warning events in the last hour across 1000 node(s) (1.0 per node).",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "events",
			Remediation: &Remediation{Command: "kubectl --context a get events --field-selector type=Warning --sort-by=.lastTimestamp -A | tail -50"},
		}},
	}, { // Test 10: Workload risks name the offending containers.
		Name:     "workload security",
		Generate: workloadSecFindings,
		Report: testReport(map[string]map[string]any{"workload-security": {"a": map[string]any{
			"privileged_containers": 1, "host_network_pods": 1, "host_pid_pods": 0,
			"run_as_root_containers": 6, "capability_additions": 1, "total_pods": 10,
			"high_risk_pods": []any{map[string]any{
				"namespace": "ns", "pod": "p", "container": "c",
				"risks": []any{"privileged", "host-network", "capabilities-add:NET_ADMIN"},
			}},
		}}}),
		WantResult: []Finding{{
			Rule: "workload-security/privileged", Title: "a has 1 privileged container(s)",
			Description: "Privileged containers have full host access. Review whether these workloads genuinely require it. Total pods: 10.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "workload-security", Affected: []string{"ns/p/c"},
			Remediation: &Remediation{Command: privilegedCommand},
		}, {
			Rule: "workload-security/host-namespaces", Title: "a has pods using host namespaces (network: 1, PID: 0)",
			Description: "Pods sharing the host network or PID namespace can see and interact with other processes and traffic on the node.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "workload-security", Affected: []string{"ns/p/c"},
		}, {
			Rule: "workload-security/run-as-root", Title: "a has 6 container(s) explicitly running as root (60%)",
			Description: "These containers have runAsUser=0 or runAsNonRoot=false set explicitly. Container escape vulnerabilities have higher impact when the workload is root.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "workload-security",
		}, {
			Rule: "workload-security/capability-add", Title: "a has 1 container(s) with added Linux capabilities",
			Description: "Containers requesting capabilities such as NET_ADMIN or SYS_PTRACE have elevated kernel access beyond the default set.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "workload-security", Affected: []string{"ns/p/c"},
		}},
	}, { // Test 11: RBAC audit names the risky bindings.
		Name:     "rbac audit",
		Generate: rbacAuditFindings,
		Report: testReport(map[string]map[string]any{"rbac-audit": {"a": map[string]any{
			"cluster_admin_bindings": 1, "wildcard_rules": 2, "default_sa_bindings": 1,
			"risk_bindings": []any{
				map[string]any{"name": "b1", "kind": "ClusterRoleBinding", "risks": []any{"cluster-admin-to-non-system"}},
				map[string]any{"name": "b2", "kind": "RoleBinding", "namespace": "ns", "risks": []any{"grants-to-default-sa"}},
			},
		}}}),
		WantResult: []Finding{{
			Rule: "rbac-audit/cluster-admin-binding", Title: "a has 1 non-system cluster-admin binding(s)",
			Description: "ClusterRoleBindings granting cluster-admin to non-system principals give unrestricted access to every resource in the cluster.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "rbac-audit", Affected: []string{"b1"},
			Remediation: &Remediation{Command: "kubectl --context a get clusterrolebinding b1 -o yaml"},
		}, {
			Rule: "rbac-audit/wildcard-rule", Title: "a has 2 RBAC rule(s) with wildcard permissions",
			Description: "Rules using '*' for verbs, resources, or apiGroups grant broader access than most workloads need.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "rbac-audit",
		}, {
			Rule: "rbac-audit/default-sa-binding", Title: "a has 1 binding(s) granting permissions to a default service account",
			Description: "The default service account is used by any pod that does not specify a different one. Granting it permissions means all unattributed workloads inherit them.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "rbac-audit", Affected: []string{"b2"},
		}},
	}, { // Test 12: Image hygiene names the mutable image; over 80% unpinned warns.
		Name:     "image audit",
		Generate: imageAuditFindings,
		Report: testReport(map[string]map[string]any{"image-audit": {"a": map[string]any{
			"latest_tag": 1, "no_digest": 9, "total_containers": 10,
			"image_risks": []any{map[string]any{
				"image": "nginx:latest", "namespace": "ns", "pod": "p", "container": "c",
				"risks": []any{"latest-tag", "no-digest"},
			}},
		}}}),
		WantResult: []Finding{{
			Rule: "image-audit/latest-tag", Title: "a has 1 container(s) using :latest or no tag",
			Description: "Out of 10 containers, 1 use :latest or omit a tag. Without a pinned tag, rollbacks and audits are unreliable.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "image-audit", Affected: []string{"nginx:latest @ ns/p/c"},
		}, {
			Rule: "image-audit/no-digest", Title: "a has 9 container(s) without digest pins (90%)",
			Description: "Images without @sha256: digest pins can change content without changing the tag. Pinning digests ensures reproducible deployments.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "image-audit",
		}},
	}, { // Test 13: Certificates split at 7 and 30 days; 7 days is a warning, 30 is clean.
		Name:     "certs",
		Generate: certFindings,
		Report: testReport(map[string]map[string]any{"certs": {"a": map[string]any{"certs": []any{
			map[string]any{"name": "tls1", "namespace": "ns", "kind": "Secret", "days_remaining": 3},
			map[string]any{"name": "tls2", "namespace": "ns", "kind": "Secret", "days_remaining": 7},
			map[string]any{"name": "tls3", "namespace": "ns", "kind": "Secret", "days_remaining": 30},
		}}}}),
		WantResult: []Finding{{
			Rule: "certs/expiring-7d", Title: "a has 1 certificate(s) expiring in fewer than 7 days",
			Description: "These TLS certificates will expire imminently. Renew them before they break webhooks, ingress, or metrics endpoints.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "certs", Affected: []string{"Secret ns/tls1 (3 days)"},
			Remediation: &Remediation{Command: "kubectl --context a get secret -A --field-selector type=kubernetes.io/tls"},
		}, {
			Rule: "certs/expiring-30d", Title: "a has 1 certificate(s) expiring within 30 days",
			Description: "Schedule renewals now to avoid expiry-driven outages.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "certs", Affected: []string{"Secret ns/tls2 (7 days)"},
		}},
	}, { // Test 14: Deprecated APIs list version, kind, count, and removal.
		Name:     "deprecated apis",
		Generate: deprecatedAPIFindings,
		Report: testReport(map[string]map[string]any{"deprecated-apis": {"a": map[string]any{"deprecated": []any{
			map[string]any{"api_version": "policy/v1beta1", "kind": "PodDisruptionBudget", "removed_in": "1.25", "instance_count": 2},
		}}}}),
		WantResult: []Finding{{
			Rule: "deprecated-apis/in-use", Title: "a uses 1 deprecated API version(s)",
			Description: "These API versions have been deprecated or removed in newer Kubernetes minor releases. Migrate before the next upgrade or workloads will fail.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "deprecated-apis",
			Affected:    []string{"policy/v1beta1 PodDisruptionBudget (2 instances, removed in 1.25)"},
			Remediation: &Remediation{Command: "kubectl --context a get --raw /metrics 2>/dev/null | grep apiserver_requested_deprecated_apis"},
		}},
	}, { // Test 15: A workload with an HPA but no PDB gets only the PDB finding.
		Name:     "coverage",
		Generate: coverageFindings,
		Report: testReport(map[string]map[string]any{"workload-coverage": {"a": map[string]any{"gaps": []any{
			map[string]any{"namespace": "ns", "name": "web", "kind": "Deployment", "has_pdb": false, "has_hpa": true},
		}}}}),
		WantResult: []Finding{{
			Rule: "workload-coverage/missing-pdb", Title: "a has 1 replicated workload(s) without a PodDisruptionBudget",
			Description: "Voluntary disruptions (node drain, kubectl drain, autoscaler) can take all replicas of these workloads down simultaneously.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "workload-coverage", Affected: []string{"Deployment ns/web"},
			Remediation: &Remediation{YAML: defaultPDBYAML},
		}},
	}, { // Test 16: An unhealthy webhook with an expiring CA yields both findings.
		Name:     "admission",
		Generate: admissionFindings,
		Report: testReport(map[string]map[string]any{"admission": {"a": map[string]any{"webhooks": []any{
			map[string]any{
				"configuration": "cfg", "webhook": "wh", "service": "ns/svc", "endpoints_healthy": false,
				"failure_policy": "Fail", "ca_bundle_days_remaining": 10,
			},
		}}}}),
		WantResult: []Finding{{
			Rule: "admission/no-healthy-endpoints", Title: "a has 1 admission webhook(s) with no healthy endpoints",
			Description: "When failurePolicy=Fail, every API request matching these webhooks will be rejected. Even with failurePolicy=Ignore, mutations and validations are silently skipped.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "admission",
			Affected:    []string{"cfg/wh (service ns/svc, failurePolicy=Fail)"},
			Remediation: &Remediation{Command: "kubectl --context a get pods -A -l app=<webhook-service-app>"},
		}, {
			Rule: "admission/ca-expiring", Title: "a has 1 admission webhook(s) with CA bundles expiring soon",
			Description: "When a webhook CA bundle expires, the apiserver refuses to talk to the webhook. Renew or rotate before the listed deadlines.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "admission", Affected: []string{"cfg/wh (CA expires in 10 days)"},
		}},
	}, { // Test 17: Node platform drift lists only the fields with several values.
		Name:     "cluster info",
		Generate: clusterInfoFindings,
		Report: testReport(map[string]map[string]any{"cluster-info": {"a": map[string]any{
			"has_drift": true, "kernel_versions": []any{"k1", "k2"}, "os_images": []any{"x"},
		}}}),
		WantResult: []Finding{{
			Rule: "cluster-info/node-platform-drift", Title: "a has node-level platform drift",
			Description: "Different nodes report different platform identities. Common cause: rolling node-pool replacement, stale AMI, or partially-completed upgrade.",
			Severity:    SeverityWarning, Cluster: "a", Scanner: "cluster-info", Affected: []string{"kernel_versions: k1, k2"},
			Remediation: &Remediation{Command: "kubectl --context a get nodes -o wide"},
		}},
	}, { // Test 18: Single-minor skew is one fleet warning listing every cluster.
		Name:     "version skew",
		Generate: versionFindings,
		Report: testReport(map[string]map[string]any{"version": {
			"a": map[string]any{"git_version": "v1.30.1"},
			"b": map[string]any{"git_version": "v1.31.0"},
		}}),
		WantResult: []Finding{{
			Rule: "version/skew", Title: "Kubernetes version skew across fleet",
			Description: "Fleet runs 2 distinct versions: v1.30.1, v1.31.0.",
			Severity:    SeverityWarning, Cluster: "fleet", Scanner: "version", Affected: []string{"a=v1.30.1", "b=v1.31.0"},
			Remediation: &Remediation{Command: "kubectl version"},
		}},
	}, { // Test 19: System namespaces are excluded from the count spread.
		Name:     "namespace spread",
		Generate: namespaceFindings,
		Report: testReport(map[string]map[string]any{"namespaces": {
			"a": map[string]any{"namespaces": []any{map[string]any{"name": "app1"}, map[string]any{"name": "kube-system"}}},
			"b": map[string]any{"namespaces": []any{map[string]any{"name": "app1"}, map[string]any{"name": "app2"}, map[string]any{"name": "app3"}}},
		}}),
		WantResult: []Finding{{
			Rule: "namespaces/non-system-count-varies", Title: "Non-system namespace count varies across the fleet",
			Description: "a has 1 non-system namespaces while b has 3. Cloud and add-on namespaces are excluded from this comparison.",
			Severity:    SeverityWarning, Cluster: "fleet", Scanner: "namespaces", Affected: []string{"a", "b"},
		}},
	}, { // Test 20: A non-uniform RBAC section is one fleet warning.
		Name:     "rbac differs",
		Generate: rbacFindings,
		Report:   testReport(map[string]map[string]any{"rbac": {"a": map[string]any{}, "b": map[string]any{}}}),
		WantResult: []Finding{{
			Rule: "rbac/config-differs", Title: "RBAC configuration differs across clusters",
			Description: "ClusterRoles, Roles, or their bindings differ between clusters. See the rbac-audit findings for named offenders.",
			Severity:    SeverityWarning, Cluster: "fleet", Scanner: "rbac",
		}},
	}, { // Test 21: Capacity status maps to a rule per status, and a group gap names itself.
		Name:     "capacity",
		Generate: capacityFindings,
		Report: &Report{Capacity: []CapacityAnalysis{
			{Cluster: "a", Status: "critical", Recommendation: "r1"},
			{
				Cluster: "b", Status: "busy", CPUUtilization: 72, MemoryUtilization: 68, Recommendation: "r2",
				GroupDeviation: `Memory is 20% points higher than group "g" average (80% vs 60%). `,
			},
		}},
		WantResult: []Finding{{
			Rule: "metrics/capacity-critical", Title: "a is in critical state", Description: "r1",
			Severity: SeverityCritical, Cluster: "a", Scanner: "metrics",
		}, {
			Rule: "metrics/capacity-busy", Title: "b is busy but healthy (CPU 72%, memory 68%)", Description: "r2",
			Severity: SeverityInfo, Cluster: "b", Scanner: "metrics",
		}, {
			Rule: "metrics/group-deviation", Title: "b deviates from group peers",
			Description: `Memory is 20% points higher than group "g" average (80% vs 60%). `,
			Severity:    SeverityWarning, Cluster: "b", Scanner: "metrics",
			Remediation: &Remediation{Command: "# Memory is 20% points higher than group \"g\" average (80% vs 60%).\nkubectl --context b top nodes"},
		}},
	}, { // Test 22: Image, event, and workload risk on one namespace is a bad deploy.
		Name:     "bad deploy",
		Generate: compositeBadDeployFindings,
		Report: testReport(map[string]map[string]any{
			"image-audit": {"a": map[string]any{"image_risks": []any{map[string]any{
				"image": "x:latest", "namespace": "ns", "pod": "p", "container": "c", "risks": []any{"latest-tag"},
			}}}},
			"events": {"a": map[string]any{"recent_warnings": []any{map[string]any{"reason": "BackOff", "namespace": "ns"}}}},
			"workload-security": {"a": map[string]any{"high_risk_pods": []any{map[string]any{
				"namespace": "ns", "pod": "p", "container": "c", "risks": []any{"privileged"},
			}}}},
		}),
		WantResult: []Finding{{
			Rule: "image-audit/bad-deploy", Title: "a shows bad-deploy signals in 1 namespace(s)",
			Description: "Image risks (mutable tags or no-digest), failure-related warning events, and workload-security risks all overlap on the same namespace. This pattern matches a recently rolled-out workload that is failing.",
			Severity:    SeverityCritical, Cluster: "a", Scanner: "image-audit", Affected: []string{"ns"},
			Remediation: &Remediation{Command: "kubectl --context a -n ns get pods,events --sort-by=.lastTimestamp"},
		}},
	}, { // Test 23: Numeric, string, set, and unknown-scanner outliers state the gap.
		Name:     "fleet outliers",
		Generate: outlierFindings,
		Report: &Report{Outliers: []OutlierResult{
			{Cluster: "c", Field: "enforced_count", Value: "4", FleetNorm: "12", Deviation: 5, Scanner: "security", Severity: SeverityCritical,
				Scope: "fleet", Kind: NormKindNumeric, Median: 12, MAD: 1.079, SampleSize: 9, Threshold: 3.5, Z: -5},
			{Cluster: "c", Field: "git_version", Value: "v1.29.0", FleetNorm: "v1.31.0", Scanner: "version", Severity: SeverityWarning,
				Scope: "fleet", Kind: NormKindString, Mode: "v1.31.0", ModeShare: 0.9, SampleSize: 10, Threshold: 0.6},
			{Cluster: "c", Field: "names", Value: "missing 2: [a b]", FleetNorm: "5 consensus items", Scanner: "crds", Severity: SeverityInfo,
				Scope: "fleet", Kind: NormKindSet, Consensus: []string{"a", "b", "c", "d", "e"}, Missing: []string{"a", "b"}, SampleSize: 10, Threshold: 0.6},
			{Cluster: "c", Field: "count", Value: "9", FleetNorm: "2.5", Scanner: "novel", Severity: SeverityInfo},
		}},
		WantResult: []Finding{{
			Rule: "security/outlier-enforced-count", Title: "c deviates from fleet norm on enforced_count",
			Description: "c reports enforced_count=4 while the fleet norm is 12 (scanner: Pod Security Standards).",
			Severity:    SeverityCritical, Cluster: "c", Scanner: "security", Affected: []string{"enforced_count"},
			Remediation: &Remediation{Command: "# enforced_count is 4 here, 8 below the fleet median of 12\n" +
				"kubectl --context c get namespaces -L pod-security.kubernetes.io/enforce"},
			Norm: &NormBasis{Scope: "fleet", Field: "enforced_count", Kind: NormKindNumeric, Median: 12, MAD: 1.079, SampleSize: 9, Threshold: 3.5, Value: "4", Z: -5},
		}, {
			Rule: "version/outlier-git-version", Title: "c deviates from fleet norm on git_version",
			Description: "c reports git_version=v1.29.0 while the fleet norm is v1.31.0 (scanner: Kubernetes Version).",
			Severity:    SeverityWarning, Cluster: "c", Scanner: "version", Affected: []string{"git_version"},
			Remediation: &Remediation{Command: "# git_version is \"v1.29.0\" here, the fleet norm is \"v1.31.0\"\nkubectl --context c version"},
			Norm:        &NormBasis{Scope: "fleet", Field: "git_version", Kind: NormKindString, Mode: "v1.31.0", ModeShare: 0.9, SampleSize: 10, Threshold: 0.6, Value: "v1.29.0"},
		}, {
			Rule: "crds/outlier-names", Title: "c deviates from fleet norm on names",
			Description: "c reports names=missing 2: [a b] while the fleet norm is 5 consensus items (scanner: Custom Resource Definitions).",
			Severity:    SeverityInfo, Cluster: "c", Scanner: "crds", Affected: []string{"names"},
			Remediation: &Remediation{Command: "# names is missing 2: [a b] of the fleet's 5 consensus items\nkubectl --context c get crds"},
			Norm: &NormBasis{Scope: "fleet", Field: "names", Kind: NormKindSet, Consensus: []string{"a", "b", "c", "d", "e"}, Missing: []string{"a", "b"},
				SampleSize: 10, Threshold: 0.6, Value: "missing 2: [a b]"},
		}, {
			Rule: "novel/outlier-count", Title: "c deviates from fleet norm on count",
			Description: "c reports count=9 while the fleet norm is 2.5 (scanner: ).",
			Severity:    SeverityInfo, Cluster: "c", Scanner: "novel", Affected: []string{"count"},
			Remediation: &Remediation{Command: "# count is 9 here, 6.5 above the fleet median of 2.5\nkubectl --context c get all -A"},
			Norm:        &NormBasis{Field: "count", Value: "9"},
		}},
	}, { // Test 24: A cohort outlier names its cohort as the norm's scope.
		Name:     "cohort outliers",
		Generate: cohortOutlierFindings,
		Report: &Report{Cohorts: []CohortSummary{{Name: "edge", Outliers: []OutlierResult{
			{Cluster: "b", Field: "crd_count", Value: "9", FleetNorm: "2", Scanner: "crds", Severity: SeverityWarning,
				Scope: "edge", Kind: NormKindNumeric, Median: 2, MAD: 1, SampleSize: 8, Threshold: 3.5, Z: 4.72},
		}}}},
		WantResult: []Finding{{
			Rule: "crds/cohort-outlier-crd-count", Title: "b deviates from its cohort on crd_count",
			Description: `Within cohort "edge", b reports crd_count=9 while the cohort norm is 2 (scanner: Custom Resource Definitions).`,
			Severity:    SeverityWarning, Cluster: "b", Scanner: "crds", Affected: []string{"crd_count"},
			Remediation: &Remediation{Command: "# crd_count is 9 here, 7 above the cohort \"edge\" median of 2\nkubectl --context b get crds"},
			Norm:        &NormBasis{Scope: "edge", Field: "crd_count", Kind: NormKindNumeric, Median: 2, MAD: 1, SampleSize: 8, Threshold: 3.5, Value: "9", Z: 4.72},
		}},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := test.Generate(test.Report)
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("findings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// normFixture returns a 10-cluster report whose security section holds two
// numeric fields with one deviant each, an absolute-rule privileged count on
// the high deviant, and every cluster tagged into one cohort.
func normFixture() (*Report, map[string]string) {
	unenforced := []float64{20, 22, 24, 24, 24, 26, 26, 28, 30, 80}
	quota := []float64{48, 49, 50, 50, 50, 51, 51, 52, 53, 2}
	perCluster := make(map[string]any, len(unenforced))
	tags := make(map[string]string, len(unenforced))
	clusters := make([]string, 0, len(unenforced))
	for i := range unenforced {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		perCluster[c] = map[string]any{"unenforced_count": unenforced[i], "quota_count": quota[i]}
		tags[c] = "edge"
	}
	r := &Report{Clusters: clusters, Sections: map[string]*SectionReport{
		"security": compare(clusters, perCluster),
		"workload-security": {PerCluster: map[string]any{"c09": map[string]any{
			"privileged_containers": 3, "total_pods": 10,
		}}},
	}}
	return r, tags
}

// TestNormProvenance verifies fleet and cohort outlier findings carry the norm
// they were measured against, with values computed by hand, and that
// absolute-rule findings carry none.
func TestNormProvenance(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	// unenforced_count: sorted 20 22 24 24 24 26 26 28 30 80, median 25.
	// Absolute deviations 1 1 1 1 1 3 3 5 5 55, MAD (1+3)/2 = 2.
	// c09 at 80: z = 0.6745 * 55 / 2 = 18.548750.
	// quota_count: sorted 2 48 49 50 50 50 51 51 52 53, median 50.
	// Absolute deviations 0 0 0 1 1 1 2 2 3 48, MAD 1.
	// c09 at 2: z = 0.6745 * -48 / 1 = -32.376.
	wantEnforced := &NormBasis{
		Scope: "fleet", Field: "unenforced_count", Kind: NormKindNumeric, Median: 25, MAD: 2, SampleSize: 10,
		Threshold: 3.5, Value: "80", Z: 18.54875,
	}
	wantQuota := &NormBasis{
		Scope: "fleet", Field: "quota_count", Kind: NormKindNumeric, Median: 50, MAD: 1, SampleSize: 10,
		Threshold: 3.5, Value: "2", Z: -32.376,
	}
	approx := cmpopts.EquateApprox(0, 1e-9)

	r, tags := normFixture()
	r.Outliers = DetectOutliers(r, 3.5)
	r.Cohorts, _ = buildCohorts(r, tags, 3.5)
	fleet := outlierFindings(r)
	byRule := map[string]Finding{}
	for _, f := range fleet {
		byRule[f.Rule] = f
	}

	tests := []struct {
		Name     string
		Finding  Finding
		WantNorm *NormBasis
	}{{ // Test 0: The high deviant reports the hand-computed median, MAD, and z.
		Name: "fleet high", Finding: byRule["security/outlier-unenforced-count"], WantNorm: wantEnforced,
	}, { // Test 1: The low deviant reports a negative z.
		Name: "fleet low", Finding: byRule["security/outlier-quota-count"], WantNorm: wantQuota,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			if test.Finding.Cluster != "c09" {
				t.Fatalf("want a finding on c09, got %+v", test.Finding)
			}
			if diff := cmp.Diff(test.WantNorm, test.Finding.Norm, approx); diff != "" {
				t.Errorf("norm mismatch (-want +got):\n%s", diff)
			}
		})
	}
	if len(fleet) != 2 {
		t.Errorf("want 2 fleet outlier findings, got %d: %+v", len(fleet), fleet)
	}

	t.Run("cohort scope", func(t *testing.T) {
		t.Parallel()
		r, tags := normFixture()
		r.Cohorts, _ = buildCohorts(r, tags, 3.5)
		got := cohortOutlierFindings(r)
		if len(got) != 2 {
			t.Fatalf("want 2 cohort findings, got %d: %+v", len(got), got)
		}
		for _, f := range got {
			want := wantEnforced
			if f.Rule == "security/cohort-outlier-quota-count" {
				want = wantQuota
			}
			want = &NormBasis{
				Scope: "edge", Field: want.Field, Kind: want.Kind, Median: want.Median, MAD: want.MAD,
				SampleSize: want.SampleSize, Threshold: want.Threshold, Value: want.Value, Z: want.Z,
			}
			if diff := cmp.Diff(want, f.Norm, approx); diff != "" {
				t.Errorf("%s norm mismatch (-want +got):\n%s", f.Rule, diff)
			}
		}
	})

	t.Run("absolute rule", func(t *testing.T) {
		t.Parallel()
		r, _ := normFixture()
		var absolute int
		for _, f := range GenerateFindings(r) {
			if strings.Contains(f.Rule, "/"+ruleOutlierPrefix) || strings.Contains(f.Rule, "/"+ruleCohortOutlierPrefix) {
				continue
			}
			absolute++
			if f.Norm != nil {
				t.Errorf("absolute finding %s carries a norm: %+v", f.Rule, f.Norm)
			}
		}
		if absolute == 0 {
			t.Fatal("fixture produced no absolute-rule finding")
		}
	})

	t.Run("brief quotes the basis", func(t *testing.T) {
		t.Parallel()
		r, _ := normFixture()
		r.Outliers = DetectOutliers(r, 3.5)
		r.Findings = GenerateFindings(r)
		brief := GenerateBrief(r)
		want := "Largest deviation: c09 unenforced_count is 80 vs a fleet median of 25 across 10 clusters."
		if !slices.Contains(brief.Lines, want) {
			t.Errorf("brief lines %q do not contain %q", brief.Lines, want)
		}
	})
}

// testNormFinding returns a fleet norm finding on scanner/field for cluster at sev.
func testNormFinding(cluster, scanner, field, sev string) Finding {
	return Finding{
		Rule: outlierRule(scanner, field, false), Severity: sev, Cluster: cluster, Scanner: scanner,
		Affected: []string{field}, Norm: &NormBasis{Scope: NormScopeFleet, Field: field},
	}
}

// testCohortNormFinding returns a norm finding on scanner/field for cluster at sev, computed over
// cohort scope.
func testCohortNormFinding(cluster, scanner, field, sev, scope string) Finding {
	f := testNormFinding(cluster, scanner, field, sev)
	f.Rule = outlierRule(scanner, field, true)
	f.Norm.Scope = scope
	return f
}

// testMembers returns the fleet scope holding every cluster named in findings.
func testMembers(findings []Finding) map[string][]string {
	var clusters []string
	for _, f := range findings {
		if !slices.Contains(clusters, f.Cluster) {
			clusters = append(clusters, f.Cluster)
		}
	}
	return map[string][]string{NormScopeFleet: clusters}
}

// testAbsoluteFinding returns an absolute-rule finding for cluster at sev.
func testAbsoluteFinding(cluster, rule, sev string) Finding {
	scanner, _, _ := strings.Cut(rule, "/")
	return Finding{Rule: rule, Severity: sev, Cluster: cluster, Scanner: scanner, Description: "Fired."}
}

// TestDropRedundant verifies one fact yields one finding: a norm finding goes when the absolute
// rule counting its field fired at an equal or higher severity, or when a field it restates is
// stated as strongly, and the absolute finding takes the dropped norm.
func TestDropRedundant(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()
	const (
		crit = SeverityCritical
		warn = SeverityWarning
		info = SeverityInfo
	)
	tests := []struct {
		Members    map[string][]string
		Findings   []Finding
		WantResult []string
	}{{ // Test 0: A memory-pressure node drops both norm findings and the absolute takes its norm.
		Findings: []Finding{
			testNormFinding("c", "node-health", "memory_pressure_nodes", crit),
			testNormFinding("c", "node-health", "unhealthy_nodes", crit),
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
		},
		WantResult: []string{"node-health/memory-pressure memory_pressure_nodes"},
	}, { // Test 1: The absolute rule listed first gives the same result.
		Findings: []Finding{
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
			testNormFinding("c", "node-health", "unhealthy_nodes", crit),
			testNormFinding("c", "node-health", "memory_pressure_nodes", crit),
		},
		WantResult: []string{"node-health/memory-pressure memory_pressure_nodes"},
	}, { // Test 2: Every version restatement goes and git_version stays.
		Findings: []Finding{
			testNormFinding("c", "version", "git_version", warn),
			testNormFinding("c", "version", "minor", warn),
			testNormFinding("c", "cluster-info", "kubelet_versions", info),
			testNormFinding("c", "deprecated-apis", "server_version", info),
		},
		WantResult: []string{"version/outlier-git-version git_version"},
	}, { // Test 3: Warning events at info go under the warning-volume rule.
		Findings: []Finding{
			testNormFinding("c", "events", "warning_events", info),
			testAbsoluteFinding("c", "events/warning-volume", warn),
		},
		WantResult: []string{"events/warning-volume warning_events"},
	}, { // Test 4: Deprecated instances at info go under the in-use rule.
		Findings: []Finding{
			testNormFinding("c", "deprecated-apis", "total_instances", info),
			testAbsoluteFinding("c", "deprecated-apis/in-use", warn),
		},
		WantResult: []string{"deprecated-apis/in-use total_instances"},
	}, { // Test 5: Cert counts collapse into the expiring rule and total_certs stays.
		Findings: []Finding{
			testNormFinding("c", "certs", "soonest_days", info),
			testNormFinding("c", "certs", "total_certs", info),
			testNormFinding("c", "certs", "warning", info),
			testAbsoluteFinding("c", "certs/expiring-30d", warn),
		},
		WantResult: []string{"certs/outlier-total-certs total_certs", "certs/expiring-30d warning"},
	}, { // Test 6: A restated field stated only at lower severity is the one dropped.
		Findings: []Finding{
			testNormFinding("c", "version", "git_version", info),
			testNormFinding("c", "version", "minor", warn),
		},
		WantResult: []string{"version/outlier-minor minor"},
	}, { // Test 7: An absolute rule below the norm finding's severity drops nothing.
		Findings: []Finding{
			testNormFinding("c", "node-health", "memory_pressure_nodes", crit),
			testAbsoluteFinding("c", "node-health/memory-pressure", warn),
		},
		WantResult: []string{
			"node-health/outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/memory-pressure ",
		},
	}, { // Test 8: Findings on different clusters never drop each other.
		Findings: []Finding{
			testNormFinding("a", "version", "minor", warn),
			testNormFinding("b", "version", "git_version", warn),
			testNormFinding("a", "node-health", "memory_pressure_nodes", crit),
			testAbsoluteFinding("b", "node-health/memory-pressure", crit),
		},
		WantResult: []string{
			"version/outlier-minor minor",
			"version/outlier-git-version git_version",
			"node-health/outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/memory-pressure ",
		},
	}, { // Test 9: Undeclared fields and absolute findings alone pass through.
		Findings: []Finding{
			testNormFinding("c", "novel", "count", warn),
			testAbsoluteFinding("c", "workload-security/privileged", crit),
		},
		WantResult: []string{"novel/outlier-count count", "workload-security/privileged "},
	}, { // Test 10: An absolute rule that also fired on a norm cluster states a shared fact, so
		// the norm finding stays beside it and the absolute takes no norm.
		Findings: []Finding{
			testNormFinding("c", "network-policies", "namespaces_without_policies", warn),
			testAbsoluteFinding("c", "network-policies/no-policy", warn),
			testAbsoluteFinding("d", "network-policies/no-policy", warn),
		},
		WantResult: []string{
			"network-policies/outlier-namespaces-without-policies namespaces_without_policies",
			"network-policies/no-policy ",
			"network-policies/no-policy ",
		},
	}, { // Test 11: An absolute rule that fired only on clusters off the norm singles them out.
		Findings: []Finding{
			testNormFinding("c", "network-policies", "namespaces_without_policies", warn),
			testNormFinding("d", "network-policies", "namespaces_without_policies", info),
			testAbsoluteFinding("c", "network-policies/no-policy", warn),
			testAbsoluteFinding("d", "network-policies/no-policy", warn),
			testAbsoluteFinding("e", "rbac-audit/wildcard-rule", warn),
		},
		WantResult: []string{
			"network-policies/no-policy namespaces_without_policies",
			"network-policies/no-policy namespaces_without_policies",
			"rbac-audit/wildcard-rule ",
		},
	}, { // Test 12: A cohort norm is judged within the cohort, so a norm cluster outside it
		// that fired the rule does not keep the finding.
		Members: map[string][]string{NormScopeFleet: {"c", "d", "e"}, "edge": {"c", "d"}},
		Findings: []Finding{
			testCohortNormFinding("c", "node-health", "memory_pressure_nodes", crit, "edge"),
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
			testAbsoluteFinding("e", "node-health/memory-pressure", crit),
		},
		WantResult: []string{
			"node-health/memory-pressure memory_pressure_nodes",
			"node-health/memory-pressure ",
		},
	}, { // Test 13: A cohort member holding the cohort norm that fired the rule keeps the finding,
		// and a fleet norm finding on that member does not count as the cohort's.
		Members: map[string][]string{NormScopeFleet: {"c", "d", "e"}, "edge": {"c", "d"}},
		Findings: []Finding{
			testCohortNormFinding("c", "node-health", "memory_pressure_nodes", crit, "edge"),
			testNormFinding("d", "node-health", "memory_pressure_nodes", crit),
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
			testAbsoluteFinding("d", "node-health/memory-pressure", crit),
		},
		WantResult: []string{
			"node-health/cohort-outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/memory-pressure ",
			"node-health/memory-pressure ",
		},
	}, { // Test 14: A restated field counted by a rule that fired on a norm cluster is still
		// stated by its own norm finding, which drops the restatement and stays.
		Findings: []Finding{
			testNormFinding("c", "node-health", "memory_pressure_nodes", crit),
			testNormFinding("c", "node-health", "unhealthy_nodes", crit),
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
			testAbsoluteFinding("d", "node-health/memory-pressure", crit),
		},
		WantResult: []string{
			"node-health/outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/memory-pressure ",
			"node-health/memory-pressure ",
		},
	}, { // Test 15: A norm whose scope is not a known population drops nothing.
		Members: map[string][]string{NormScopeFleet: {"c"}},
		Findings: []Finding{
			testCohortNormFinding("c", "node-health", "memory_pressure_nodes", crit, "gone"),
			testAbsoluteFinding("c", "node-health/memory-pressure", crit),
		},
		WantResult: []string{
			"node-health/cohort-outlier-memory-pressure-nodes memory_pressure_nodes",
			"node-health/memory-pressure ",
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			members := test.Members
			if members == nil {
				members = testMembers(test.Findings)
			}
			var got []string
			for _, f := range dropRedundant(slices.Clone(test.Findings), members) {
				field := ""
				if f.Norm != nil {
					field = f.Norm.Field
				}
				got = append(got, f.Rule+" "+field)
			}
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDropRedundantStatesNorm verifies an absolute finding that takes a norm says it in its
// description.
func TestDropRedundantStatesNorm(t *testing.T) {
	t.Parallel()
	n := testNormFinding("c", "node-health", "memory_pressure_nodes", SeverityCritical)
	n.Norm = &NormBasis{
		Scope: NormScopeFleet, Field: "memory_pressure_nodes", Kind: NormKindNumeric,
		ModeShare: 25.0 / 26, SampleSize: 26, Value: "2", Exact: true,
	}
	findings := []Finding{n, testAbsoluteFinding("c", "node-health/memory-pressure", SeverityCritical)}
	got := dropRedundant(findings, testMembers(findings))
	want := "Fired. memory_pressure_nodes is 2 on c, where every other cluster in the fleet " +
		"reports exactly 0."
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if diff := cmp.Diff(want, got[0].Description); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

// TestNormLine verifies the brief's norm line for each kind and scope.
func TestNormLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Findings   []Finding
		WantResult string
	}{{ // Test 0: No finding carries a norm.
		Findings: []Finding{{Severity: SeverityCritical, Cluster: "a", Rule: "node-health/not-ready"}},
	}, { // Test 1: Severity outranks deviation.
		Findings: []Finding{
			{Severity: SeverityInfo, Cluster: "a",
				Norm: &NormBasis{Scope: "fleet", Field: "x", Kind: NormKindNumeric, Median: 1, SampleSize: 9, Value: "90", Z: 90}},
			{Severity: SeverityWarning, Cluster: "b",
				Norm: &NormBasis{Scope: "fleet", Field: "y", Kind: NormKindNumeric, Median: 12, SampleSize: 26, Value: "30", Z: 4}},
		},
		WantResult: "Largest deviation: b y is 30 vs a fleet median of 12 across 26 clusters.",
	}, { // Test 2: A cohort string norm quotes the mode and its share.
		Findings: []Finding{{Severity: SeverityWarning, Cluster: "a",
			Norm: &NormBasis{Scope: "edge", Field: "git_version", Kind: NormKindString, Mode: "v1.31.0", ModeShare: 0.875, SampleSize: 8, Value: "v1.29.0"}}},
		WantResult: `Largest deviation: a git_version is "v1.29.0" vs the cohort "edge" mode of "v1.31.0" held by 88% of 8 clusters.`,
	}, { // Test 3: A set norm counts the missing consensus members.
		Findings: []Finding{{Severity: SeverityInfo, Cluster: "a",
			Norm: &NormBasis{Scope: "fleet", Field: "names", Kind: NormKindSet, Consensus: []string{"a", "b", "c"}, Missing: []string{"b"}, SampleSize: 10}}},
		WantResult: "Largest deviation: a names lacks 1 of the 3 members the fleet holds in common across 10 clusters.",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, normLine(test.Findings)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFingerprintFollowsRule verifies the fingerprint is a hash of cluster,
// scanner, and rule: a count change in the title keeps it, a different
// cluster changes it, and GenerateFindings stamps it on every finding.
func TestFingerprintFollowsRule(t *testing.T) {
	t.Parallel()

	privileged := func(cluster string, n int) *Report {
		return testReport(map[string]map[string]any{"workload-security": {cluster: map[string]any{
			"privileged_containers": n, "total_pods": 10,
		}}})
	}
	three := GenerateFindings(privileged("a", 3))
	four := GenerateFindings(privileged("a", 4))
	other := GenerateFindings(privileged("b", 3))
	if len(three) != 1 || len(four) != 1 || len(other) != 1 {
		t.Fatalf("want one finding each, got %d, %d, %d", len(three), len(four), len(other))
	}

	tests := []struct {
		WantEqual bool
		A, B      Finding
	}{{ // Test 0: Count 3 and count 4 on one cluster share a fingerprint.
		WantEqual: true, A: three[0], B: four[0],
	}, { // Test 1: The same check on another cluster does not.
		WantEqual: false, A: three[0], B: other[0],
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if test.A.Title == test.B.Title && test.A.Cluster == test.B.Cluster {
				t.Fatalf("fixture titles must differ: %q", test.A.Title)
			}
			if got := test.A.Fingerprint == test.B.Fingerprint; got != test.WantEqual {
				t.Errorf("fingerprints equal = %v, want %v (%s vs %s)", got, test.WantEqual, test.A.Fingerprint, test.B.Fingerprint)
			}
			want := util.Fingerprint(test.A.Cluster, test.A.Scanner, test.A.Rule)
			if diff := cmp.Diff(want, test.A.Fingerprint); diff != "" {
				t.Errorf("stamped fingerprint mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRuleTitle verifies fixed and field-derived rules get labels free of
// cluster names and counts, and every catalog rule is scanner/slug.
func TestRuleTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Rule       string
		WantResult string
	}{{ // Test 0: Fixed rule from the catalog.
		Rule: "workload-security/privileged", WantResult: "Privileged containers",
	}, { // Test 1: Fleet outlier rule.
		Rule: "security/outlier-enforced-count", WantResult: "Deviates from the fleet norm on enforced_count",
	}, { // Test 2: Cohort outlier rule is not read as a fleet outlier.
		Rule: "crds/cohort-outlier-crd-count", WantResult: "Deviates from its cohort on crd_count",
	}, { // Test 3: Self-drift rule.
		Rule: "events/self-drift-warning-events", WantResult: "warning_events broke from its own baseline",
	}, { // Test 4: Trend rule.
		Rule: "events/trend-warning-events", WantResult: "warning_events is trending",
	}, { // Test 5: Unknown rule is returned unchanged.
		Rule: "novel/thing", WantResult: "novel/thing",
	}, { // Test 6: A string without a scanner is returned unchanged.
		Rule: "bare", WantResult: "bare",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, RuleTitle(test.Rule)); diff != "" {
				t.Errorf("title mismatch (-want +got):\n%s", diff)
			}
		})
	}

	for rule := range ruleTitles {
		scannerName, slug, ok := strings.Cut(rule, "/")
		if !ok || slug == "" || strings.ContainsAny(slug, "_ ") {
			t.Errorf("rule %q is not scanner/slug", rule)
		}
		if _, known := ScannerLabels[scannerName]; !known && scannerName != "cohort" {
			t.Errorf("rule %q names unknown scanner %q", rule, scannerName)
		}
	}
}

// TestHistoryFindingRules verifies trend and self-drift findings carry a
// field-derived rule and a stamped fingerprint.
func TestHistoryFindingRules(t *testing.T) {
	t.Parallel()

	trend := GenerateTrendFindings([]ClusterTrend{{
		Cluster: "a", Scanner: "events", Field: "warning_events", Direction: TrendWorsening,
		Points: []TrendPoint{{Value: 1}, {Value: 9}},
	}}, nil)
	drift := SelfDriftFindings([]SelfDrift{{Cluster: "a", Scanner: "events", Field: "warning_events", Baseline: 1, Latest: 9}})

	tests := []struct {
		Findings []Finding
		WantRule string
	}{{ // Test 0: Cluster trend.
		Findings: trend, WantRule: "events/trend-warning-events",
	}, { // Test 1: Self drift.
		Findings: drift, WantRule: "events/self-drift-warning-events",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if len(test.Findings) != 1 {
				t.Fatalf("want one finding, got %d", len(test.Findings))
			}
			f := test.Findings[0]
			if diff := cmp.Diff(test.WantRule, f.Rule); diff != "" {
				t.Errorf("rule mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(util.Fingerprint("a", "events", test.WantRule), f.Fingerprint); diff != "" {
				t.Errorf("fingerprint mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// fleetResults builds scanner results for clusters c00 to c<n-1> from one
// payload per cluster, all under scannerName.
func fleetResults(scannerName string, payloads []map[string]any) ([]string, map[string]map[string]scanner.Result) {
	clusters := make([]string, 0, len(payloads))
	results := make(map[string]map[string]scanner.Result, len(payloads))
	for i, p := range payloads {
		c := fmt.Sprintf("c%02d", i)
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{scannerName: {Scanner: scannerName, Data: p}}
	}
	return clusters, results
}

// ruleHit is the part of a finding the set and vulnerability tests pin.
type ruleHit struct {
	// Rule is the finding's rule.
	Rule string
	// Cluster is the finding's cluster.
	Cluster string
	// Severity is the finding's severity.
	Severity string
	// Missing is the finding's Norm.Missing, for set findings.
	Missing []string
}

// TestSetAndVulnerabilityRules builds whole reports and checks which findings
// the CRD, service, ingress-class, vulnerability, and policy-report scanners
// produce, by rule.
func TestSetAndVulnerabilityRules(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()

	crd := func(names ...string) map[string]any {
		items := make([]any, 0, len(names))
		for _, n := range names {
			items = append(items, map[string]any{"name": n, "group": "g", "versions": []any{"v1"}, "scope": "Namespaced"})
		}
		return map[string]any{"count": len(names), "crds": items}
	}
	svc := func(names ...string) map[string]any {
		items := make([]any, 0, len(names))
		for _, n := range names {
			ns, name, _ := strings.Cut(n, "/")
			items = append(items, map[string]any{"namespace": ns, "name": name, "type": "ClusterIP"})
		}
		return map[string]any{"count": len(names), "services": items}
	}
	ing := func(classes ...string) map[string]any {
		items := make([]any, 0, len(classes))
		for i, c := range classes {
			items = append(items, map[string]any{"namespace": "web", "name": fmt.Sprintf("i%d", i), "ingress_class_name": c})
		}
		return map[string]any{"count": len(classes), "ingresses": items}
	}
	vuln := func(available bool, critical int) map[string]any {
		image := "api:1"
		if critical > 20 {
			image = "api:2"
		}
		return map[string]any{
			"available": available, "reports": 4, "critical": critical, "high": 5, "medium": 9, "low": 2, "unknown": 0,
			"top_images": []any{map[string]any{"namespace": "web", "workload": "api", "image": image, "critical": 3}},
		}
	}
	policy := func(fail int) map[string]any {
		return map[string]any{
			"available": true, "reports": 3, "total_fail": fail, "total_warn": 1, "total_error": 0,
			"by_source": []any{map[string]any{"source": "kyverno", "fail": fail}},
		}
	}
	cm := []string{"certificates.cert-manager.io", "issuers.cert-manager.io"}

	tests := []struct {
		Scanner    string
		Payloads   []map[string]any
		WantResult []ruleHit
	}{{ // Test 0: One of ten clusters lacks a CRD the other nine have; a CRD on two clusters is not consensus.
		Scanner: "crds",
		Payloads: []map[string]any{
			crd(cm...), crd(cm...), crd(cm...), crd(cm...), crd(cm...),
			crd(cm...), crd(cm...), crd(append(cm, "foo.example.com")...), crd(append(cm, "foo.example.com")...),
			crd("certificates.cert-manager.io"),
		},
		// The CRD count is 2 on seven of ten, an exact norm, so c07, c08, and c09 are off it.
		WantResult: []ruleHit{{
			Rule: "crds/missing-consensus", Cluster: "c09", Severity: SeverityWarning,
			Missing: []string{"issuers.cert-manager.io"},
		}, {Rule: "crds/outlier-count", Cluster: "c07", Severity: SeverityInfo},
			{Rule: "crds/outlier-count", Cluster: "c08", Severity: SeverityInfo},
			{Rule: "crds/outlier-count", Cluster: "c09", Severity: SeverityInfo}},
	}, { // Test 1: A cluster missing a service the fleet runs is info.
		Scanner: "services",
		Payloads: []map[string]any{
			svc("default/kubernetes", "monitoring/prometheus"), svc("default/kubernetes", "monitoring/prometheus"),
			svc("default/kubernetes", "monitoring/prometheus"), svc("default/kubernetes"),
			svc("default/kubernetes", "monitoring/prometheus"), svc("default/kubernetes", "monitoring/prometheus"),
			svc("default/kubernetes", "monitoring/prometheus"), svc("default/kubernetes", "monitoring/prometheus"),
			svc("default/kubernetes", "monitoring/prometheus"), svc("default/kubernetes", "monitoring/prometheus"),
		},
		// The service count is 2 on nine of ten, an exact norm, so c03 is off it too.
		WantResult: []ruleHit{{
			Rule: "services/missing-consensus", Cluster: "c03", Severity: SeverityInfo,
			Missing: []string{"monitoring/prometheus"},
		}, {Rule: "services/outlier-count", Cluster: "c03", Severity: SeverityWarning}},
	}, { // Test 2: A cluster on another ingress class is flagged; one with no ingresses is not.
		Scanner: "ingresses",
		Payloads: []map[string]any{
			ing("nginx"), ing("nginx"), ing("nginx"), ing("nginx"), ing("nginx"),
			ing("nginx"), ing("nginx"), ing("nginx"), ing("traefik"), ing(),
		},
		// The ingress count is 1 on nine of ten, an exact norm, so c09 with none is off it.
		WantResult: []ruleHit{{
			Rule: "ingresses/missing-consensus", Cluster: "c08", Severity: SeverityInfo,
			Missing: []string{"nginx"},
		}, {Rule: "ingresses/outlier-count", Cluster: "c09", Severity: SeverityInfo}},
	}, { // Test 3: A critical CVE count far above the fleet is a warning, every CVE is an info, and a cluster without the scanner is not a zero.
		Scanner: "vulnerabilities",
		Payloads: []map[string]any{
			vuln(true, 10), vuln(true, 11), vuln(true, 11), vuln(true, 12), vuln(true, 12),
			vuln(true, 12), vuln(true, 13), vuln(true, 13), vuln(true, 14), vuln(true, 40), vuln(false, 0),
		},
		WantResult: []ruleHit{
			{Rule: "vulnerabilities/critical-outlier", Cluster: "c09", Severity: SeverityWarning},
			{Rule: "vulnerabilities/critical-present", Cluster: "c00", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c01", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c02", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c03", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c04", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c05", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c06", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c07", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c08", Severity: SeverityInfo},
			{Rule: "vulnerabilities/critical-present", Cluster: "c09", Severity: SeverityInfo},
			{Rule: "vulnerabilities/outlier-available", Cluster: "c10", Severity: SeverityInfo},
		},
	}, { // Test 4: A policy failure count far above the fleet is a warning.
		Scanner: "policy-reports",
		Payloads: []map[string]any{
			policy(10), policy(11), policy(11), policy(12), policy(12),
			policy(12), policy(13), policy(13), policy(14), policy(60),
		},
		WantResult: []ruleHit{
			{Rule: "policy-reports/fail-outlier", Cluster: "c09", Severity: SeverityWarning},
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := fleetResults(test.Scanner, test.Payloads)
			r := Build(clusters, results)
			var got []ruleHit
			for _, f := range r.Findings {
				if f.Scanner != test.Scanner {
					continue
				}
				h := ruleHit{Rule: f.Rule, Cluster: f.Cluster, Severity: f.Severity}
				if f.Norm != nil {
					h.Missing = f.Norm.Missing
				}
				got = append(got, h)
			}
			sort.Slice(got, func(i, j int) bool {
				if got[i].Rule != got[j].Rule {
					return got[i].Rule < got[j].Rule
				}
				return got[i].Cluster < got[j].Cluster
			})
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("findings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestOutlierRule verifies named fields get their own rule and every other
// field keeps the field-derived slug, in both scopes.
func TestOutlierRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Scanner    string
		Field      string
		Cohort     bool
		WantResult string
	}{{ // Test 0: CRD set, fleet scope.
		Scanner: "crds", Field: "crd_names", WantResult: "crds/missing-consensus",
	}, { // Test 1: CRD set, cohort scope.
		Scanner: "crds", Field: "crd_names", Cohort: true, WantResult: "crds/cohort-missing-consensus",
	}, { // Test 2: Critical CVE count.
		Scanner: "vulnerabilities", Field: "critical", WantResult: "vulnerabilities/critical-outlier",
	}, { // Test 3: Policy failures, cohort scope.
		Scanner: "policy-reports", Field: "total_fail", Cohort: true, WantResult: "policy-reports/cohort-fail-outlier",
	}, { // Test 4: An unnamed field keeps the derived slug.
		Scanner: "vulnerabilities", Field: "medium", WantResult: "vulnerabilities/outlier-medium",
	}, { // Test 5: An unnamed field in a cohort keeps the derived cohort slug.
		Scanner: "crds", Field: "count", Cohort: true, WantResult: "crds/cohort-outlier-count",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := outlierRule(test.Scanner, test.Field, test.Cohort)
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("rule mismatch (-want +got):\n%s", diff)
			}
			if title := RuleTitle(got); title == got {
				t.Errorf("rule %q has no title", got)
			}
		})
	}
}

// TestVersionMarks verifies the skew finding names only the clusters off a
// clear majority version, at the severity of their own skew from it.
func TestVersionMarks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Versions     map[string]string
		WantMajority string
		WantMarks    []ClusterMark
	}{{ // Test 0: One cluster a minor behind is a warning mark.
		Versions:     map[string]string{"a": "v1.31.2", "b": "v1.31.2", "c": "v1.30.4"},
		WantMajority: "v1.31.2",
		WantMarks:    []ClusterMark{{Cluster: "c", Severity: SeverityWarning}},
	}, { // Test 1: Two minors behind is critical, one minor is a warning.
		Versions:     map[string]string{"a": "v1.31.0", "b": "v1.31.0", "c": "v1.29.1", "d": "v1.30.0"},
		WantMajority: "v1.31.0",
		WantMarks: []ClusterMark{
			{Cluster: "c", Severity: SeverityCritical},
			{Cluster: "d", Severity: SeverityWarning},
		},
	}, { // Test 2: A tie for most common version names no majority.
		Versions: map[string]string{"a": "v1.30.1", "b": "v1.31.0"},
	}, { // Test 3: A patch-only difference marks nothing.
		Versions:     map[string]string{"a": "v1.31.2", "b": "v1.31.2", "c": "v1.31.1"},
		WantMajority: "v1.31.2",
	}, { // Test 4: A cluster with no version reading is neither counted nor marked.
		Versions:     map[string]string{"a": "v1.31.0", "b": "", "c": "v1.31.0", "d": "v1.30.0"},
		WantMajority: "v1.31.0",
		WantMarks:    []ClusterMark{{Cluster: "d", Severity: SeverityWarning}},
	}, { // Test 5: A cluster ahead of the majority is marked too.
		Versions:     map[string]string{"a": "v1.30.0", "b": "v1.30.0", "c": "v1.31.0"},
		WantMajority: "v1.30.0",
		WantMarks:    []ClusterMark{{Cluster: "c", Severity: SeverityWarning}},
	}, { // Test 6: No versions at all.
		Versions: map[string]string{},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters := make([]string, 0, len(test.Versions))
			for c := range test.Versions {
				clusters = append(clusters, c)
			}
			sort.Strings(clusters)
			gotMajority, gotMarks := versionMarks(clusters, test.Versions)
			if diff := cmp.Diff(test.WantMajority, gotMajority); diff != "" {
				t.Errorf("majority mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantMarks, gotMarks, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("marks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestVersionFindingsMarks verifies the skew finding carries its marks and
// names the off-majority clusters in its description.
func TestVersionFindingsMarks(t *testing.T) {
	t.Parallel()
	r := testReport(map[string]map[string]any{"version": {
		"a": map[string]any{"git_version": "v1.31.0"},
		"b": map[string]any{"git_version": "v1.31.0"},
		"c": map[string]any{"git_version": "v1.30.2"},
	}})
	got := versionFindings(r)
	want := []Finding{{
		Rule: "version/skew", Title: "Kubernetes version skew across fleet",
		Description: "Fleet runs 2 distinct versions: v1.30.2, v1.31.0. Off the majority version v1.31.0: c.",
		Severity:    SeverityWarning, Cluster: "fleet", Scanner: "version",
		Affected:    []string{"a=v1.31.0", "b=v1.31.0", "c=v1.30.2"},
		Marks:       []ClusterMark{{Cluster: "c", Severity: SeverityWarning}},
		Remediation: &Remediation{Command: "kubectl version"},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
	status := map[string]string{}
	for _, h := range GenerateClusterHealth(r, got) {
		status[h.Name] = h.Status
	}
	if diff := cmp.Diff(map[string]string{"a": "healthy", "b": "healthy", "c": "degraded"}, status); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
}

// TestClusterHealthOwnFindings verifies a cluster's status and counts come
// from its own findings, so a fleet-scoped finding marks no cluster.
func TestClusterHealthOwnFindings(t *testing.T) {
	t.Parallel()
	r := &Report{Clusters: []string{"a", "b"}}
	tests := []struct {
		WantStatus map[string]string
		Findings   []Finding
	}{{ // Test 0: Fleet-scoped warning only.
		Findings:   []Finding{{Cluster: "fleet", Severity: SeverityWarning, Rule: "version/skew"}},
		WantStatus: map[string]string{"a": "healthy", "b": "healthy"},
	}, { // Test 1: Fleet-scoped critical and one cluster warning.
		Findings: []Finding{
			{Cluster: "fleet", Severity: SeverityCritical, Rule: "version/skew"},
			{Cluster: "b", Severity: SeverityWarning, Rule: "certs/expiring-30d"},
		},
		WantStatus: map[string]string{"a": "healthy", "b": "degraded"},
	}, { // Test 2: A cluster critical.
		Findings:   []Finding{{Cluster: "a", Severity: SeverityCritical, Rule: "node-health/not-ready"}},
		WantStatus: map[string]string{"a": "critical", "b": "healthy"},
	}, { // Test 3: A fleet finding sets status on the cluster it marks only.
		Findings: []Finding{{
			Cluster: "fleet", Severity: SeverityCritical, Rule: "version/skew",
			Marks: []ClusterMark{{Cluster: "b", Severity: SeverityWarning}},
		}},
		WantStatus: map[string]string{"a": "healthy", "b": "degraded"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := map[string]string{}
			for _, h := range GenerateClusterHealth(r, test.Findings) {
				got[h.Name] = h.Status
			}
			if diff := cmp.Diff(test.WantStatus, got); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
