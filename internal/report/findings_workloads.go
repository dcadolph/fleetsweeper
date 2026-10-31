package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

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
		latestTag, latestObs := observeInt(r, "image-audit", cluster, "latest_tag")
		noDigest, noDigestObs := observeInt(r, "image-audit", cluster, "no_digest")
		total, totalObs := observeInt(r, "image-audit", cluster, "total_containers")

		if latestObs.seen() && latestTag > 0 {
			affected := filterImagesByRisk(risks, "latest-tag")
			findings = append(findings, Finding{
				Rule:        "image-audit/latest-tag",
				Title:       fmt.Sprintf("%s has %d container(s) using :latest or no tag", cluster, latestTag),
				Description: fmt.Sprintf("Out of %d containers, %d use :latest or omit a tag. Without a pinned tag, rollbacks and audits are unreliable.", total, latestTag) + weakest(latestObs, totalObs).note(),
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "image-audit",
				Affected:    affected,
			})
		}
		digestObs := weakest(noDigestObs, totalObs)
		if digestObs.seen() && noDigest > 0 && total > 0 {
			pct := float64(noDigest) / float64(total) * 100
			sev := SeverityInfo
			if pct > 80 {
				sev = SeverityWarning
			}
			findings = append(findings, Finding{
				Rule:        "image-audit/no-digest",
				Title:       fmt.Sprintf("%s has %d container(s) without digest pins (%.0f%%)", cluster, noDigest, pct),
				Description: "Images without @sha256: digest pins can change content without changing the tag. Pinning digests ensures reproducible deployments." + digestObs.note(),
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
	m, obs := clusterView(r, "image-audit", cluster)
	if !obs.seen() {
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
// given risk tag, capped at maxAffected entries.
func filterImagesByRisk(images []imageRisk, risk string) []string {
	var matches []string
	for _, ir := range images {
		if slices.Contains(ir.Risks, risk) {
			matches = append(matches, fmt.Sprintf("%s @ %s", ir.Image, ir.Where))
		}
	}
	return capList(matches)
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
		m, obs := clusterView(r, "workload-coverage", cluster)
		if obs != observed {
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
				Rule:        "workload-coverage/missing-pdb",
				Title:       fmt.Sprintf("%s has %d replicated workload(s) without a PodDisruptionBudget", cluster, len(missingPDB)),
				Description: "Voluntary disruptions (node drain, kubectl drain, autoscaler) can take all replicas of these workloads down simultaneously.",
				Severity:    SeverityWarning,
				Cluster:     cluster,
				Scanner:     "workload-coverage",
				Affected:    capList(missingPDB),
				Remediation: &Remediation{
					YAML: defaultPDBYAML,
				},
			})
		}
		if len(missingHPA) > 0 {
			findings = append(findings, Finding{
				Rule:        "workload-coverage/missing-hpa",
				Title:       fmt.Sprintf("%s has %d replicated workload(s) without a HorizontalPodAutoscaler", cluster, len(missingHPA)),
				Description: "These workloads cannot scale with load. If they are CPU- or memory-bound, expect throttling or OOMKills under traffic spikes.",
				Severity:    SeverityInfo,
				Cluster:     cluster,
				Scanner:     "workload-coverage",
				Affected:    capList(missingHPA),
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
		"Failed":                 true,
		"BackOff":                true,
		"CrashLoopBackOff":       true,
		"FailedScheduling":       true,
		"Killing":                true,
		"Pulling":                true,
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
			Rule:        "image-audit/bad-deploy",
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
	m, obs := clusterView(r, "events", cluster)
	if !obs.seen() {
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
