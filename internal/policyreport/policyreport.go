// Package policyreport converts Fleetsweeper findings into PolicyReport CRs
// using the wgpolicyk8s.io/v1alpha2 schema, the CNCF-standard format consumed
// by Kyverno, Trivy Operator, Falco Sidekick, and the Policy Reporter UI.
// Emitting this format lets existing policy-report dashboards ingest
// Fleetsweeper findings without any custom adapter.
//
// As with the FleetDriftReport emitter, this package writes only to the
// local filesystem. What an operator does with the YAML next (commit,
// kubectl apply, ship to a separate cluster) is their choice.
package policyreport

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// APIVersion is the v1alpha2 PolicyReport API group/version. Stable across
// PolicyReporter, Kyverno, and Trivy adopters as of 2024.
const APIVersion = "wgpolicyk8s.io/v1alpha2"

// Kind is the PolicyReport CRD kind.
const Kind = "PolicyReport"

// Source identifies Fleetsweeper as the producer of the report results so
// dashboards can filter or group by tool.
const Source = "fleetsweeper"

// PolicyReport is the on-disk shape of a wgpolicyk8s.io/v1alpha2 PolicyReport
// resource. Only the fields Fleetsweeper populates are modelled; the upstream
// CRD has more optional fields, but additive omission is forward-compatible.
type PolicyReport struct {
	// APIVersion identifies the resource group/version.
	APIVersion string `json:"apiVersion"`
	// Kind identifies the resource type.
	Kind string `json:"kind"`
	// Metadata holds the standard ObjectMeta projection relevant for GitOps.
	Metadata Metadata `json:"metadata"`
	// Summary holds per-result counts for quick dashboards.
	Summary Summary `json:"summary"`
	// Results is the list of policy results in this report.
	Results []Result `json:"results,omitempty"`
}

// Metadata is the standard ObjectMeta projection. Namespace is required: the
// upstream PolicyReport CRD is Namespaced.
type Metadata struct {
	// Name is unique within the namespace.
	Name string `json:"name"`
	// Namespace places the report; required for the Namespaced PolicyReport CRD.
	Namespace string `json:"namespace"`
	// Labels are propagated for selector-based queries.
	Labels map[string]string `json:"labels,omitempty"`
}

// Summary mirrors the v1alpha2 summary block. We do not currently emit
// "pass" results, so Pass is always 0; we expose the field anyway so the
// shape matches what tooling expects.
type Summary struct {
	// Pass is the count of result=pass entries.
	Pass int `json:"pass"`
	// Fail is the count of result=fail entries.
	Fail int `json:"fail"`
	// Warn is the count of result=warn entries.
	Warn int `json:"warn"`
	// Error is the count of result=error entries.
	Error int `json:"error"`
	// Skip is the count of result=skip entries.
	Skip int `json:"skip"`
}

// Result is one finding rendered as a v1alpha2 PolicyReport result entry.
type Result struct {
	// Source identifies the policy engine that produced the result.
	Source string `json:"source"`
	// Policy is the policy or rule family the result applies to.
	Policy string `json:"policy"`
	// Rule is the specific check within Policy.
	Rule string `json:"rule,omitempty"`
	// Category groups related results in the UI.
	Category string `json:"category,omitempty"`
	// Severity is critical, high, medium, low, or info.
	Severity string `json:"severity"`
	// Result is one of pass, fail, warn, error, skip.
	Result string `json:"result"`
	// Message is the human-readable explanation.
	Message string `json:"message"`
	// Timestamp is when the finding was produced.
	Timestamp Timestamp `json:"timestamp"`
	// Resources references the affected Kubernetes resources, if known.
	Resources []ResourceRef `json:"resources,omitempty"`
	// Properties carries arbitrary key/value metadata, including the
	// Fleetsweeper remediation hint when one is available.
	Properties map[string]string `json:"properties,omitempty"`
}

// Timestamp is the v1alpha2 timestamp object (seconds + nanos), distinct
// from a plain RFC3339 string.
type Timestamp struct {
	// Seconds is the Unix epoch second.
	Seconds int64 `json:"seconds"`
	// Nanos is the nanosecond offset within Seconds.
	Nanos int32 `json:"nanos"`
}

// ResourceRef points at a single Kubernetes object the result concerns. We
// fill what we can from the finding's Affected list; ambiguous entries are
// rendered with just a Name.
type ResourceRef struct {
	// APIVersion is the object's apiVersion when known.
	APIVersion string `json:"apiVersion,omitempty"`
	// Kind is the object's kind when known.
	Kind string `json:"kind,omitempty"`
	// Namespace is the object's namespace when known.
	Namespace string `json:"namespace,omitempty"`
	// Name is the object's name. Always set.
	Name string `json:"name"`
}

// nameSanitize keeps Kubernetes DNS-1123 characters; runs of others collapse to a dash.
var nameSanitize = regexp.MustCompile(`[^a-z0-9.-]+`)

// collapseDashes squashes runs of dashes into a single dash for readability.
var collapseDashes = regexp.MustCompile(`-{2,}`)

// ReportsFor builds one PolicyReport per cluster from r. The namespace argument
// is required by the upstream CRD; pass the operator's preferred namespace
// (typically "fleetsweeper" or "policy-reporter"). Fleet-scoped findings are
// duplicated onto every cluster report so reconcilers do not need to special-
// case an aggregate.
func ReportsFor(r *report.Report, scanID, namespace string) []PolicyReport {
	if r == nil {
		return nil
	}
	if namespace == "" {
		namespace = "fleetsweeper"
	}

	findingsByCluster := groupFindings(r.Findings)
	scanTime, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		scanTime = time.Now().UTC()
	}

	out := make([]PolicyReport, 0, len(r.Clusters))
	for _, cluster := range r.Clusters {
		fs := append([]report.Finding{}, findingsByCluster[cluster]...)
		fs = append(fs, findingsByCluster["fleet"]...)
		results := make([]Result, 0, len(fs))
		for _, f := range fs {
			results = append(results, toResult(f, scanTime))
		}

		out = append(out, PolicyReport{
			APIVersion: APIVersion,
			Kind:       Kind,
			Metadata: Metadata{
				Name:      "fleetsweeper-" + sanitizeName(cluster),
				Namespace: namespace,
				Labels: map[string]string{
					"fleetsweeper.io/cluster":      cluster,
					"fleetsweeper.io/scan-id":      scanID,
					"app.kubernetes.io/managed-by": "fleetsweeper",
					"policy.kubernetes.io/engine":  "fleetsweeper",
				},
			},
			Summary: summarize(results),
			Results: results,
		})
	}
	return out
}

// Write marshals reports to YAML, one file per cluster, into dir.
func Write(reports []PolicyReport, dir string) error {
	if dir == "" {
		return fmt.Errorf("policyreport: output dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for _, r := range reports {
		path := filepath.Join(dir, r.Metadata.Name+".yaml")
		data, err := yaml.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", r.Metadata.Name, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// toResult converts a Fleetsweeper Finding into a PolicyReport result entry.
func toResult(f report.Finding, ts time.Time) Result {
	res := Result{
		Source:    Source,
		Policy:    f.Scanner,
		Rule:      ruleFromTitle(f.Title),
		Category:  categoryForScanner(f.Scanner),
		Severity:  severityMap(f.Severity),
		Result:    resultMap(f.Severity),
		Message:   f.Title,
		Timestamp: Timestamp{Seconds: ts.Unix(), Nanos: int32(ts.Nanosecond())},
	}
	if f.Description != "" {
		res.Message = f.Title + " -- " + f.Description
	}
	for _, name := range f.Affected {
		res.Resources = append(res.Resources, parseResourceRef(name))
	}
	if f.Remediation != nil {
		res.Properties = map[string]string{}
		if f.Remediation.Command != "" {
			res.Properties["remediation.command"] = f.Remediation.Command
		}
		if f.Remediation.YAML != "" {
			res.Properties["remediation.yaml"] = f.Remediation.YAML
		}
		if f.Remediation.RunbookURL != "" {
			res.Properties["remediation.runbook_url"] = f.Remediation.RunbookURL
		}
	}
	if f.Cluster != "" && f.Cluster != "fleet" {
		if res.Properties == nil {
			res.Properties = map[string]string{}
		}
		res.Properties["fleetsweeper.cluster"] = f.Cluster
	}
	return res
}

// severityMap translates Fleetsweeper severities to the v1alpha2 vocabulary.
func severityMap(sev string) string {
	switch sev {
	case report.SeverityCritical:
		return "critical"
	case report.SeverityWarning:
		return "medium"
	case report.SeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// resultMap translates Fleetsweeper severities to the v1alpha2 result vocab.
// Both critical and warning findings are failures; info is a warn so
// dashboards can surface them without colouring the summary red.
func resultMap(sev string) string {
	switch sev {
	case report.SeverityCritical, report.SeverityWarning:
		return "fail"
	default:
		return "warn"
	}
}

// categoryForScanner returns a coarse category label for grouping in policy
// dashboards. Maps Fleetsweeper scanner names onto the same buckets the
// HTML report uses on the Categories section.
func categoryForScanner(scanner string) string {
	switch scanner {
	case "security", "workload-security", "rbac-audit", "rbac", "network-policies":
		return "Security & Access"
	case "node-health", "metrics", "resources", "resource-quotas":
		return "Health & Resources"
	case "version", "namespaces", "crds", "clusterinfo":
		return "Cluster Info"
	case "services", "ingresses", "image-audit":
		return "Workloads"
	case "events":
		return "Events"
	case "certs", "admission", "deprecated-apis":
		return "Cluster Configuration"
	}
	return "Other"
}

// ruleFromTitle extracts a short rule name from a finding title. Used to
// populate the optional Rule field; helpful when filtering results in
// Policy Reporter UI.
func ruleFromTitle(title string) string {
	// Truncate at the first colon or dash to keep rule names short and stable.
	for _, sep := range []string{":", " -- ", " has "} {
		if idx := strings.Index(title, sep); idx > 0 {
			return strings.TrimSpace(title[:idx])
		}
	}
	if len(title) > 60 {
		return title[:60]
	}
	return title
}

// parseResourceRef does best-effort parsing of the "namespace/name" or
// "Kind ns/name" shapes Fleetsweeper findings use in Affected. Falls back
// to Name-only when the shape is unrecognized.
func parseResourceRef(s string) ResourceRef {
	s = strings.TrimSpace(s)
	if s == "" {
		return ResourceRef{Name: "(unknown)"}
	}
	// "Kind ns/name" pattern.
	if parts := strings.SplitN(s, " ", 2); len(parts) == 2 {
		if strings.Contains(parts[1], "/") {
			nameParts := strings.SplitN(parts[1], "/", 2)
			if nameParts[1] != "" {
				return ResourceRef{Kind: parts[0], Namespace: nameParts[0], Name: nameParts[1]}
			}
		}
	}
	// "ns/name" pattern.
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		if len(parts) == 2 && !strings.ContainsAny(parts[0], " ") && parts[1] != "" {
			return ResourceRef{Namespace: parts[0], Name: parts[1]}
		}
	}
	return ResourceRef{Name: s}
}

// groupFindings buckets findings by cluster, fanning fleet-scoped findings
// into the empty key so callers can copy them onto every cluster's report.
func groupFindings(findings []report.Finding) map[string][]report.Finding {
	out := map[string][]report.Finding{}
	for _, f := range findings {
		key := f.Cluster
		if key == "" {
			key = "fleet"
		}
		out[key] = append(out[key], f)
	}
	return out
}

// summarize counts result types for the report's Summary field.
func summarize(results []Result) Summary {
	var s Summary
	for _, r := range results {
		switch r.Result {
		case "pass":
			s.Pass++
		case "fail":
			s.Fail++
		case "warn":
			s.Warn++
		case "error":
			s.Error++
		case "skip":
			s.Skip++
		}
	}
	return s
}

// sanitizeName returns a DNS-1123-safe rendering of cluster.
func sanitizeName(cluster string) string {
	lower := strings.ToLower(cluster)
	cleaned := nameSanitize.ReplaceAllString(lower, "-")
	cleaned = collapseDashes.ReplaceAllString(cleaned, "-")
	cleaned = strings.Trim(cleaned, "-.")
	if cleaned == "" {
		return "unnamed"
	}
	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}
	return cleaned
}
