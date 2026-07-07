// Package policyreportingest reads wgpolicyk8s.io PolicyReport and
// ClusterPolicyReport custom resources written by other tools (Kyverno,
// Gatekeeper, Trivy, kube-bench) and aggregates their fail/warn results
// per cluster. Closes the loop with Fleetsweeper's own PolicyReport
// emission so a single dashboard can show "what every policy tool
// across the fleet is complaining about right now."
package policyreportingest

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "policy-reports"

// policyReportGVR points at the namespaced PolicyReport resource.
var policyReportGVR = schema.GroupVersionResource{
	Group:    "wgpolicyk8s.io",
	Version:  "v1alpha2",
	Resource: "policyreports",
}

// clusterPolicyReportGVR points at the cluster-scoped variant.
var clusterPolicyReportGVR = schema.GroupVersionResource{
	Group:    "wgpolicyk8s.io",
	Version:  "v1alpha2",
	Resource: "clusterpolicyreports",
}

// resultCategory classifies one PolicyReport result row by source tool.
// The scanner labels each result with the source that produced the
// containing PolicyReport so the dashboard can break down failures by
// vendor: "Kyverno: 14 failing, Gatekeeper: 3 failing."
type sourceTally struct {
	// Source identifies the producing tool: kyverno, gatekeeper, trivy,
	// kubebench, or "other" when the source label is missing.
	Source string `json:"source"`
	// Pass is the count of policy results with result=pass.
	Pass int `json:"pass"`
	// Fail is the count of policy results with result=fail.
	Fail int `json:"fail"`
	// Warn is the count of policy results with result=warn.
	Warn int `json:"warn"`
	// Error is the count of policy results with result=error.
	Error int `json:"error"`
	// Skip is the count of policy results with result=skip.
	Skip int `json:"skip"`
}

// PolicyFailure is one top-offender policy across the cluster. The
// dashboard surfaces the worst-N so operators can focus on the policies
// firing most often.
type PolicyFailure struct {
	// Source is the producing tool.
	Source string `json:"source"`
	// Policy is the policy name.
	Policy string `json:"policy"`
	// Rule is the specific rule that fired. Empty for tools that don't
	// emit per-rule attribution.
	Rule string `json:"rule,omitempty"`
	// Fail is the count of fail results for this (source, policy, rule).
	Fail int `json:"fail"`
	// Warn is the count of warn results for the same tuple.
	Warn int `json:"warn"`
	// Severity is the highest severity seen across the contributing rows.
	Severity string `json:"severity,omitempty"`
}

// Data holds the per-cluster PolicyReport aggregate.
type Data struct {
	// Available is true when the wgpolicyk8s.io CRDs were discoverable.
	// When false the rest of the fields stay zero so consumers can tell
	// "no policy tool installed" from "policy tools installed and clean."
	Available bool `json:"available"`
	// Reports is the count of PolicyReport CRs read.
	Reports int `json:"reports"`
	// ClusterReports is the count of ClusterPolicyReport CRs read.
	ClusterReports int `json:"cluster_reports"`
	// TotalFail is the cluster-wide count of result=fail rows.
	TotalFail int `json:"total_fail"`
	// TotalWarn is the cluster-wide count of result=warn rows.
	TotalWarn int `json:"total_warn"`
	// TotalError is the count of result=error rows (broken policy).
	TotalError int `json:"total_error"`
	// BySource breaks down results by producing tool.
	BySource []sourceTally `json:"by_source"`
	// TopFailures lists the policies firing most often, descending.
	TopFailures []PolicyFailure `json:"top_failures"`
}

// NewScanner returns a Scanner that reads both PolicyReport and
// ClusterPolicyReport resources. Safe to register unconditionally; the
// scanner returns Available=false when neither CRD is installed.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		data := Data{}
		bySource := map[string]*sourceTally{}
		topMap := map[string]*PolicyFailure{}

		nsList, nsErr := client.Dynamic().Resource(policyReportGVR).
			List(ctx, metav1.ListOptions{ResourceVersion: "0"})
		clList, clErr := client.Dynamic().Resource(clusterPolicyReportGVR).
			List(ctx, metav1.ListOptions{ResourceVersion: "0"})

		nsAbsent := !crdAvailable(nsErr)
		clAbsent := !crdAvailable(clErr)

		// Both CRDs not installed means the feature is genuinely absent, a
		// trustworthy "nothing here" rather than a failed read.
		if nsAbsent && clAbsent {
			return scanner.Result{
				Scanner: Name,
				State:   scanner.StateUnavailable,
				Reason:  "wgpolicyk8s.io PolicyReport CRDs not installed",
				Data:    data,
			}, nil
		}
		data.Available = true

		if nsList != nil {
			data.Reports = len(nsList.Items)
			for i := range nsList.Items {
				ingestReport(&nsList.Items[i], &data, bySource, topMap)
			}
		}
		if clList != nil {
			data.ClusterReports = len(clList.Items)
			for i := range clList.Items {
				ingestReport(&clList.Items[i], &data, bySource, topMap)
			}
		}

		data.BySource = finalizeSourceTallies(bySource)
		data.TopFailures = finalizeTopFailures(topMap, 20)

		// A real error (not "CRD absent") on one list while the other was
		// reachable means we hold partial data, so report degraded rather
		// than letting missing reports read as a clean cluster.
		var degraded []string
		if nsErr != nil && !nsAbsent {
			degraded = append(degraded, fmt.Sprintf("policy reports: %v", nsErr))
		}
		if clErr != nil && !clAbsent {
			degraded = append(degraded, fmt.Sprintf("cluster policy reports: %v", clErr))
		}
		if len(degraded) > 0 {
			return scanner.Result{
				Scanner: Name,
				State:   scanner.StateDegraded,
				Reason:  "partial data: " + strings.Join(degraded, "; "),
				Data:    data,
			}, nil
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// crdAvailable reports whether the dynamic-client error indicates the
// CRD is registered. The two "no such resource" errors look different
// when surfaced through the dynamic client; both should suppress.
func crdAvailable(err error) bool {
	if err == nil {
		return true
	}
	if meta.IsNoMatchError(err) {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "could not find the requested resource") ||
		strings.Contains(msg, "no matches for kind") {
		return false
	}
	// Other errors (RBAC denied, timeout) are still treated as
	// "available but unreadable"; the scanner returns zero counts.
	return true
}

// ingestReport folds one report's results into the running aggregate.
func ingestReport(obj *unstructured.Unstructured, data *Data, bySource map[string]*sourceTally, topMap map[string]*PolicyFailure) {
	results, _, _ := unstructured.NestedSlice(obj.Object, "results")
	for _, raw := range results {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		source := stringField(row, "source")
		if source == "" {
			source = "other"
		}
		policy := stringField(row, "policy")
		rule := stringField(row, "rule")
		result := stringField(row, "result")
		severity := stringField(row, "severity")

		ts := bySource[source]
		if ts == nil {
			ts = &sourceTally{Source: source}
			bySource[source] = ts
		}
		switch result {
		case "pass":
			ts.Pass++
		case "fail":
			ts.Fail++
			data.TotalFail++
			updateTop(topMap, source, policy, rule, severity, "fail")
		case "warn":
			ts.Warn++
			data.TotalWarn++
			updateTop(topMap, source, policy, rule, severity, "warn")
		case "error":
			ts.Error++
			data.TotalError++
		case "skip":
			ts.Skip++
		}
	}
}

// updateTop accumulates the (source, policy, rule) tuple into the
// top-failures index.
func updateTop(topMap map[string]*PolicyFailure, source, policy, rule, severity, result string) {
	if policy == "" {
		return
	}
	key := source + "|" + policy + "|" + rule
	entry := topMap[key]
	if entry == nil {
		entry = &PolicyFailure{Source: source, Policy: policy, Rule: rule, Severity: severity}
		topMap[key] = entry
	}
	switch result {
	case "fail":
		entry.Fail++
	case "warn":
		entry.Warn++
	}
	if severityRank(severity) > severityRank(entry.Severity) {
		entry.Severity = severity
	}
}

// severityRank orders the PolicyReport severity strings so the most
// alarming wins when collapsing across rows.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// stringField returns a string field from an unstructured row map.
func stringField(row map[string]any, key string) string {
	v, _ := row[key].(string)
	return v
}

// finalizeSourceTallies returns the source tallies sorted by Fail
// descending so the worst tool appears first.
func finalizeSourceTallies(in map[string]*sourceTally) []sourceTally {
	out := make([]sourceTally, 0, len(in))
	for _, ts := range in {
		out = append(out, *ts)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Fail != out[j].Fail {
			return out[i].Fail > out[j].Fail
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// finalizeTopFailures returns the worst-N PolicyFailure entries.
func finalizeTopFailures(in map[string]*PolicyFailure, limit int) []PolicyFailure {
	out := make([]PolicyFailure, 0, len(in))
	for _, pf := range in {
		out = append(out, *pf)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Fail != out[j].Fail {
			return out[i].Fail > out[j].Fail
		}
		if out[i].Warn != out[j].Warn {
			return out[i].Warn > out[j].Warn
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
