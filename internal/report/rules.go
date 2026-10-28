package report

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Rule slug prefixes for checks derived from a scanner field rather than a
// fixed check. The field follows the prefix in hyphenated form.
const (
	ruleOutlierPrefix       = "outlier-"
	ruleCohortOutlierPrefix = "cohort-outlier-"
	ruleTrendPrefix         = "trend-"
	ruleSelfDriftPrefix     = "self-drift-"
)

// ruleTitles maps every fixed rule to a label that names no cluster and no
// count, so a recommendation spanning many clusters reads correctly.
var ruleTitles = map[string]string{
	"version/skew":                       "Kubernetes version skew across the fleet",
	"namespaces/non-system-count-varies": "Non-system namespace count varies across the fleet",
	"rbac/config-differs":                "RBAC configuration differs across clusters",
	"node-health/memory-pressure":        "Nodes under memory pressure",
	"node-health/disk-pressure":          "Nodes under disk pressure",
	"node-health/not-ready":              "Nodes not ready",
	"metrics/capacity-critical":          "Cluster capacity is critical",
	"metrics/capacity-degraded":          "Cluster capacity is degraded",
	"metrics/capacity-busy":              "Cluster is busy but healthy",
	"metrics/group-deviation":            "Utilization deviates from group peers",
	"security/psa-unenforced":            "Namespaces without Pod Security enforcement",
	"network-policies/no-policy":         "Namespaces with no network policies",
	"resource-quotas/no-quota":           "No resource quotas defined",
	"events/warning-volume":              "Warning events in the last hour",
	"workload-security/privileged":       "Privileged containers",
	"workload-security/host-namespaces":  "Pods using host namespaces",
	"workload-security/run-as-root":      "Containers explicitly running as root",
	"workload-security/capability-add":   "Containers with added Linux capabilities",
	"rbac-audit/cluster-admin-binding":   "Non-system cluster-admin bindings",
	"rbac-audit/wildcard-rule":           "RBAC rules with wildcard permissions",
	"rbac-audit/default-sa-binding":      "Bindings that grant a default service account",
	"image-audit/latest-tag":             "Containers using :latest or no tag",
	"image-audit/no-digest":              "Containers without digest pins",
	"image-audit/bad-deploy":             "Bad-deploy signals",
	"certs/expiring-7d":                  "Certificates expiring in fewer than 7 days",
	"certs/expiring-30d":                 "Certificates expiring within 30 days",
	"deprecated-apis/in-use":             "Deprecated API versions in use",
	"workload-coverage/missing-pdb":      "Replicated workloads without a PodDisruptionBudget",
	"workload-coverage/missing-hpa":      "Replicated workloads without a HorizontalPodAutoscaler",
	"admission/no-healthy-endpoints":     "Admission webhooks with no healthy endpoints",
	"admission/ca-expiring":              "Admission webhook CA bundles expiring soon",
	"cluster-info/node-platform-drift":   "Node-level platform drift",
	"cohort/wrong-cohort":                "Cluster may be in the wrong cohort",

	// Named fleet-relative and vulnerability rules.
	"vulnerabilities/critical-present":        "Images with critical vulnerabilities",
	"crds/missing-consensus":                  "Missing CRDs most of the fleet has",
	"crds/cohort-missing-consensus":           "Missing CRDs most of its cohort has",
	"services/missing-consensus":              "Missing services most of the fleet runs",
	"services/cohort-missing-consensus":       "Missing services most of its cohort runs",
	"ingresses/missing-consensus":             "Missing ingress classes most of the fleet uses",
	"ingresses/cohort-missing-consensus":      "Missing ingress classes most of its cohort uses",
	"vulnerabilities/critical-outlier":        "Critical vulnerability count deviates from the fleet norm",
	"vulnerabilities/cohort-critical-outlier": "Critical vulnerability count deviates from its cohort",
	"vulnerabilities/high-outlier":            "High vulnerability count deviates from the fleet norm",
	"vulnerabilities/cohort-high-outlier":     "High vulnerability count deviates from its cohort",
	"policy-reports/fail-outlier":             "Policy failure count deviates from the fleet norm",
	"policy-reports/cohort-fail-outlier":      "Policy failure count deviates from its cohort",
}

// namedOutlierRules gives the fleet-relative check on a few fields a rule of
// its own instead of the field-derived "outlier-<field>" slug, keyed by
// "<scanner>/<field>". The cohort variant inserts "cohort-" before the slug.
var namedOutlierRules = map[string]string{
	"crds/crd_names":            "missing-consensus",
	"services/service_names":    "missing-consensus",
	"ingresses/ingress_classes": "missing-consensus",
	"vulnerabilities/critical":  "critical-outlier",
	"vulnerabilities/high":      "high-outlier",
	"policy-reports/total_fail": "fail-outlier",
}

// outlierRule returns the rule of a fleet-relative finding on field, or of a
// within-cohort finding when cohort is set.
func outlierRule(scannerName, field string, cohort bool) string {
	if slug, ok := namedOutlierRules[scannerName+"/"+field]; ok {
		if cohort {
			return scannerName + "/cohort-" + slug
		}
		return scannerName + "/" + slug
	}
	if cohort {
		return fieldRule(scannerName, ruleCohortOutlierPrefix, field)
	}
	return fieldRule(scannerName, ruleOutlierPrefix, field)
}

// fieldRule returns the rule for a check derived from a scanner field, e.g.
// fieldRule("security", ruleOutlierPrefix, "enforced_count") is
// "security/outlier-enforced-count".
func fieldRule(scannerName, prefix, field string) string {
	return scannerName + "/" + prefix + strings.ReplaceAll(field, "_", "-")
}

// RuleTitle returns a label for a rule that names no cluster and no count.
// Field-derived rules are described from their field. An unknown rule is
// returned unchanged.
func RuleTitle(rule string) string {
	if t, ok := ruleTitles[rule]; ok {
		return t
	}
	_, slug, ok := strings.Cut(rule, "/")
	if !ok {
		return rule
	}
	for _, p := range []struct{ prefix, format string }{
		{ruleCohortOutlierPrefix, "Deviates from its cohort on %s"},
		{ruleOutlierPrefix, "Deviates from the fleet norm on %s"},
		{ruleSelfDriftPrefix, "%s broke from its own baseline"},
		{ruleTrendPrefix, "%s is trending"},
	} {
		if field, found := strings.CutPrefix(slug, p.prefix); found {
			return fmt.Sprintf(p.format, strings.ReplaceAll(field, "-", "_"))
		}
	}
	return rule
}

// FindingFingerprint returns the stable identifier of a finding: a hash of its
// cluster, scanner, and rule. It never reads the title, so counts in the title
// can change without orphaning acks or breaking persistence.
func FindingFingerprint(f Finding) string {
	return util.Fingerprint(f.Cluster, f.Scanner, f.Rule)
}

// stampFingerprints sets each finding's Fingerprint from its cluster, scanner,
// and rule, and returns the same slice.
func stampFingerprints(fs []Finding) []Finding {
	for i := range fs {
		fs[i].Fingerprint = FindingFingerprint(fs[i])
	}
	return fs
}

// scannerInspect maps a scanner to the kubectl arguments that show the
// resources its fields count, so a norm remediation can point at them.
var scannerInspect = map[string]string{
	"version":           "version",
	"namespaces":        "get namespaces",
	"crds":              "get crds",
	"services":          "get services -A",
	"ingresses":         "get ingress -A",
	"resources":         "get nodes -o wide",
	"rbac":              "get clusterroles,clusterrolebindings",
	"security":          "get namespaces -L pod-security.kubernetes.io/enforce",
	"network-policies":  "get networkpolicies -A",
	"resource-quotas":   "get resourcequotas,limitranges -A",
	"node-health":       "get nodes",
	"metrics":           "top nodes",
	"events":            "get events -A --field-selector type=Warning --sort-by=.lastTimestamp",
	"workload-security": "get pods -A -o wide",
	"rbac-audit":        "get clusterrolebindings -o wide",
	"image-audit":       "get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,POD:.metadata.name,IMAGES:.spec.containers[*].image",
	"certs":             "get secrets -A --field-selector type=kubernetes.io/tls",
	"deprecated-apis":   "get --raw /metrics",
	"workload-coverage": "get pdb,hpa -A",
	"cluster-info":      "get nodes -o wide",
	"admission":         "get validatingwebhookconfigurations,mutatingwebhookconfigurations",
	"geo":               "get nodes -L topology.kubernetes.io/region,topology.kubernetes.io/zone",
	"vulnerabilities":   "get vulnerabilityreports -A",
	"policy-reports":    "get policyreports -A",
}

// normRemediation builds the remediation for an outlier finding. The first
// line states the gap between the cluster's value and the norm of scope
// ("fleet" or a cohort description), the second inspects the resources the
// field counts on that cluster.
func normRemediation(o OutlierResult, scope string) *Remediation {
	inspect, ok := scannerInspect[o.Scanner]
	if !ok {
		inspect = "get all -A"
	}
	return &Remediation{
		Command: fmt.Sprintf("# %s\nkubectl --context %s %s", normGap(o, scope), o.Cluster, inspect),
	}
}

// exactNormPhrase states an exact numeric norm as who holds it: "every other cluster in
// <scope> reports exactly <norm>" when one cluster differs, or "<k> of <n> clusters in
// <scope> report exactly <norm>" otherwise.
func exactNormPhrase(share float64, n int, norm, scope string) string {
	k := int(math.Round(share * float64(n)))
	if k == n-1 {
		return fmt.Sprintf("every other cluster in %s reports exactly %s", scope, norm)
	}
	return fmt.Sprintf("%d of %d clusters in %s report exactly %s", k, n, scope, norm)
}

// normGap describes how far an outlier sits from the norm of scope. Numeric
// fields state the signed distance from the median, set fields the missing
// consensus members, and string fields the norm value.
func normGap(o OutlierResult, scope string) string {
	if o.Exact {
		return fmt.Sprintf("%s is %s here, %s", o.Field, o.Value,
			exactNormPhrase(o.ModeShare, o.SampleSize, o.FleetNorm, "the "+scope))
	}
	switch o.Kind {
	case NormKindNumeric:
		v, err := strconv.ParseFloat(o.Value, 64)
		if err != nil {
			break
		}
		dir := "above"
		if v < o.Median {
			dir = "below"
		}
		return fmt.Sprintf("%s is %s here, %s %s the %s median of %s",
			o.Field, o.Value, formatNum(math.Abs(v-o.Median)), dir, scope, formatNum(o.Median))
	case NormKindSet:
		return fmt.Sprintf("%s is missing %d: %v of the %s's %d consensus items",
			o.Field, len(o.Missing), o.Missing, scope, len(o.Consensus))
	}
	return fmt.Sprintf("%s is %q here, the %s norm is %q", o.Field, o.Value, scope, o.FleetNorm)
}
