package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

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
			// A namespace total below the unenforced count means the total
			// is missing, so the share is unknown rather than over 100%.
			share := fmt.Sprintf("%d namespaces", unenforced)
			sev := SeverityWarning
			if total >= unenforced {
				pct := float64(unenforced) / float64(total) * 100
				share = fmt.Sprintf("%d of %d namespaces (%.0f%%)", unenforced, total, pct)
				if pct > 50 {
					sev = SeverityCritical
				}
			}
			names := unenforcedNamespaces(r, cluster)
			cmd := fmt.Sprintf("kubectl --context %s label namespace <ns> "+
				"pod-security.kubernetes.io/enforce=baseline --overwrite", cluster)
			if len(names) > 0 {
				cmd = fmt.Sprintf("kubectl --context %s label namespace %s "+
					"pod-security.kubernetes.io/enforce=baseline --overwrite",
					cluster, strings.Join(names[:min(len(names), maxAffected)], " "))
			}
			findings = append(findings, Finding{
				Rule:        "security/psa-unenforced",
				Title:       fmt.Sprintf("%s has %d namespace(s) without Pod Security enforcement", cluster, unenforced),
				Description: share + " have no Pod Security Standards enforce label. Pods in these namespaces can run with any privileges.",
				Severity:    sev,
				Cluster:     cluster,
				Scanner:     "security",
				Affected:    capList(names),
				Remediation: &Remediation{Command: cmd},
			})
		}
	}
	return findings
}

// unenforcedNamespaces returns the names of namespaces with no enforce level in a cluster's
// security payload, or nil when the payload has no namespaces list.
func unenforcedNamespaces(r *Report, cluster string) []string {
	raw, _ := clusterData(r, "security", cluster)["namespaces"].([]any)
	var out []string
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["namespace"].(string)
		enforce, _ := entry["enforce"].(string)
		if name != "" && enforce == "" {
			out = append(out, name)
		}
	}
	return out
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
				Rule:        "network-policies/no-policy",
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

// workloadSecFindings emits per-cluster security findings naming the
// offending pods, so the reader sees which pods are privileged and not only
// how many.
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
				Rule:        "workload-security/privileged",
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
				Rule:        "workload-security/host-namespaces",
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
				Rule:        "workload-security/run-as-root",
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
				Rule:        "workload-security/capability-add",
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
	m := clusterData(r, "workload-security", cluster)
	if m == nil {
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

// maxAffected is the most Affected entries a finding lists before the "and N more" suffix.
const maxAffected = 10

// filterRiskNames returns the names of pods carrying the given risk tag, capped
// at maxAffected entries with an "and N more" suffix when truncated.
func filterRiskNames(pods []highRiskPod, tag string) []string {
	var matches []string
	for _, p := range pods {
		for _, r := range p.Risks {
			if strings.HasPrefix(r, tag) {
				matches = append(matches, p.Name)
				break
			}
		}
	}
	return capList(matches)
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
				Rule:        "rbac-audit/cluster-admin-binding",
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
				Rule:        "rbac-audit/wildcard-rule",
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
				Rule:        "rbac-audit/default-sa-binding",
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
	m := clusterData(r, "rbac-audit", cluster)
	if m == nil {
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
// risk, capped at maxAffected entries.
func filterBindingsByRisk(bs []riskBinding, risk string) []string {
	var matches []string
	for _, b := range bs {
		if slices.Contains(b.Risks, risk) {
			matches = append(matches, b.Name)
		}
	}
	return capList(matches)
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
		m := clusterData(r, "certs", cluster)
		if m == nil {
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
			remaining, _ := util.Float64(entry["days_remaining"])
			days := int(remaining)
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
				Rule:        "certs/expiring-7d",
				Title:       fmt.Sprintf("%s has %d certificate(s) expiring in fewer than 7 days", cluster, len(critical)),
				Description: "These TLS certificates will expire imminently. Renew them before they break webhooks, ingress, or metrics endpoints.",
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "certs",
				Affected:    capList(critical),
				Remediation: &Remediation{
					Command: fmt.Sprintf("kubectl --context %s get secret -A --field-selector type=kubernetes.io/tls", cluster),
				},
			})
		}
		if len(warning) > 0 {
			findings = append(findings, Finding{
				Rule:        "certs/expiring-30d",
				Title:       fmt.Sprintf("%s has %d certificate(s) expiring within 30 days", cluster, len(warning)),
				Description: "Schedule renewals now to avoid expiry-driven outages.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "certs",
				Affected:    capList(warning),
			})
		}
	}
	return findings
}

// vulnerabilityFindings reports every cluster whose vulnerability scanner found
// at least one critical CVE. It is an absolute rule at info severity: the
// fleet-relative critical-outlier rule says whether the count is unusual, this
// one says the CVEs exist at all.
func vulnerabilityFindings(r *Report) []Finding {
	sec := r.Sections["vulnerabilities"]
	if sec == nil {
		return nil
	}
	flat := flattenSection(r.Clusters, sec)
	var findings []Finding
	for _, cluster := range r.Clusters {
		m := flat[cluster]
		if available, _ := m["available"].(bool); !available {
			continue
		}
		count, _ := util.Float64(m["critical"])
		critical := int(count)
		if critical <= 0 {
			continue
		}
		var images []string
		raw, _ := m["top_images"].([]any)
		for _, item := range raw {
			img, ok := item.(map[string]any)
			if !ok {
				continue
			}
			imgCritical, _ := util.Float64(img["critical"])
			if imgCritical <= 0 {
				continue
			}
			name, _ := img["image"].(string)
			images = append(images, fmt.Sprintf("%s (%d critical)", name, int(imgCritical)))
		}
		findings = append(findings, Finding{
			Rule:        "vulnerabilities/critical-present",
			Title:       fmt.Sprintf("%s runs images with %d critical vulnerabilities", cluster, critical),
			Description: "The cluster's vulnerability reports list critical CVEs in running images. Rebuild or upgrade the images and redeploy.",
			Severity:    SeverityInfo,
			Cluster:     cluster,
			Scanner:     "vulnerabilities",
			Affected:    capList(images),
			Remediation: &Remediation{
				Command: fmt.Sprintf("kubectl --context %s %s", cluster, scannerInspect["vulnerabilities"]),
			},
		})
	}
	return findings
}

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
		m := clusterData(r, "admission", cluster)
		if m == nil {
			continue
		}
		raw, _ := m["webhooks"].([]any)
		var unhealthy, expiring []string
		var firstSvc string
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
			caRemaining, _ := util.Float64(entry["ca_bundle_days_remaining"])
			caDays := int(caRemaining)
			label := cfg + "/" + whName
			if !healthy && svc != "" {
				if firstSvc == "" {
					firstSvc = svc
				}
				unhealthy = append(unhealthy, fmt.Sprintf("%s (service %s, failurePolicy=%s)", label, svc, failurePolicy))
			}
			if caDays >= 0 && caDays < 30 {
				expiring = append(expiring, fmt.Sprintf("%s (CA expires in %d days)", label, caDays))
			}
		}
		if len(unhealthy) > 0 {
			cmd := fmt.Sprintf("kubectl --context %s get endpoints -A", cluster)
			if ns, name, ok := strings.Cut(firstSvc, "/"); ok {
				cmd = fmt.Sprintf("kubectl --context %s -n %s get endpoints %s", cluster, ns, name)
			}
			findings = append(findings, Finding{
				Rule:        "admission/no-healthy-endpoints",
				Title:       fmt.Sprintf("%s has %d admission webhook(s) with no healthy endpoints", cluster, len(unhealthy)),
				Description: "When failurePolicy=Fail, every API request matching these webhooks will be rejected. Even with failurePolicy=Ignore, mutations and validations are silently skipped.",
				Severity:    SeverityCritical,
				Cluster:     cluster,
				Scanner:     "admission",
				Affected:    capList(unhealthy),
				Remediation: &Remediation{Command: cmd},
			})
		}
		if len(expiring) > 0 {
			findings = append(findings, Finding{
				Rule:        "admission/ca-expiring",
				Title:       fmt.Sprintf("%s has %d admission webhook(s) with CA bundles expiring soon", cluster, len(expiring)),
				Description: "When a webhook CA bundle expires, the apiserver refuses to talk to the webhook. Renew or rotate before the listed deadlines.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "admission",
				Affected:    capList(expiring),
			})
		}
	}
	return findings
}
