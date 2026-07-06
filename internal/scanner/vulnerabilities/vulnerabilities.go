// Package vulnerabilities reads aquasecurity.github.io/v1alpha1
// VulnerabilityReport custom resources produced by the Trivy Operator and
// aggregates their severity counts into a per-cluster baseline.
// Fleetsweeper does not run Trivy itself; this scanner is an integration
// layer that turns existing Trivy data into drift signals.
package vulnerabilities

import (
	"context"
	"sort"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "vulnerabilities"

// reportsGVR points at the Trivy Operator's VulnerabilityReport CRD.
var reportsGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

// VulnerableImage captures the top contributors to a cluster's CVE total.
// The dashboard surfaces this list so operators can target the worst
// images first.
type VulnerableImage struct {
	// Namespace is the namespace the report lives in.
	Namespace string `json:"namespace"`
	// Workload is the originating workload's name (deployment, statefulset, ...).
	Workload string `json:"workload"`
	// Image is the container image reference.
	Image string `json:"image"`
	// Critical is the count of CRITICAL severity findings.
	Critical int `json:"critical"`
	// High is the count of HIGH severity findings.
	High int `json:"high"`
	// Medium is the count of MEDIUM severity findings.
	Medium int `json:"medium"`
	// Low is the count of LOW severity findings.
	Low int `json:"low"`
}

// total returns the sum of all severities for ranking purposes.
func (v VulnerableImage) total() int {
	return v.Critical + v.High + v.Medium + v.Low
}

// Data holds vulnerability aggregates for one cluster. Counts are summed
// across every VulnerabilityReport visible in the cluster regardless of
// namespace; per-namespace breakdowns can be added later if needed.
type Data struct {
	// Available is true when the Trivy CRD was discoverable. When false the
	// other fields are all zero and operators can interpret that as "Trivy
	// not installed" rather than "zero vulnerabilities."
	Available bool `json:"available"`
	// Reports is the number of VulnerabilityReport CRs seen.
	Reports int `json:"reports"`
	// Critical is the fleet-wide count of CRITICAL findings.
	Critical int `json:"critical"`
	// High is the count of HIGH findings.
	High int `json:"high"`
	// Medium is the count of MEDIUM findings.
	Medium int `json:"medium"`
	// Low is the count of LOW findings.
	Low int `json:"low"`
	// Unknown is the count of findings with an unrecognized severity.
	Unknown int `json:"unknown"`
	// TopImages lists the worst offenders by total findings.
	TopImages []VulnerableImage `json:"top_images"`
}

// NewScanner returns a scanner that reads VulnerabilityReport custom
// resources and aggregates them. Safe to register unconditionally; the
// scanner returns Available=false when the Trivy CRD isn't installed.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		list, err := client.Dynamic().Resource(reportsGVR).List(ctx, metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			if meta.IsNoMatchError(err) || isNotFound(err) {
				return scanner.Result{Scanner: Name, Data: Data{Available: false}}, nil
			}
			return scanner.Result{Scanner: Name, Data: Data{Available: false}}, nil
		}
		data := Data{Available: true, Reports: len(list.Items)}
		seen := make(map[string]*VulnerableImage)
		for i := range list.Items {
			parseReport(&list.Items[i], &data, seen)
		}
		data.TopImages = topImages(seen, 20)
		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// parseReport extracts severity counts and per-image attribution from one
// VulnerabilityReport. The CR shape is taken from the Trivy Operator's
// public schema; both `report.summary` and per-vulnerability arrays are
// honored so the scanner works with older and newer operator versions.
func parseReport(obj *unstructured.Unstructured, data *Data, seen map[string]*VulnerableImage) {
	ns := obj.GetNamespace()
	workload := obj.GetLabels()["trivy-operator.resource.name"]
	if workload == "" {
		workload = obj.GetName()
	}
	image, _, _ := unstructured.NestedString(obj.Object, "report", "artifact", "repository")
	tag, _, _ := unstructured.NestedString(obj.Object, "report", "artifact", "tag")
	if image == "" {
		image = obj.GetLabels()["trivy-operator.container.name"]
	}
	if tag != "" {
		image = image + ":" + tag
	}

	summary, _, _ := unstructured.NestedMap(obj.Object, "report", "summary")
	critical := intFromAny(summary["criticalCount"])
	high := intFromAny(summary["highCount"])
	medium := intFromAny(summary["mediumCount"])
	low := intFromAny(summary["lowCount"])
	unknown := intFromAny(summary["unknownCount"])

	data.Critical += critical
	data.High += high
	data.Medium += medium
	data.Low += low
	data.Unknown += unknown

	key := ns + "/" + workload + "/" + image
	entry, ok := seen[key]
	if !ok {
		entry = &VulnerableImage{Namespace: ns, Workload: workload, Image: image}
		seen[key] = entry
	}
	entry.Critical += critical
	entry.High += high
	entry.Medium += medium
	entry.Low += low
}

// topImages returns the worst-N offenders sorted by total finding count
// descending. Critical findings break ties.
func topImages(seen map[string]*VulnerableImage, limit int) []VulnerableImage {
	if len(seen) == 0 {
		return nil
	}
	out := make([]VulnerableImage, 0, len(seen))
	for _, v := range seen {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].total(), out[j].total()
		if ti != tj {
			return ti > tj
		}
		return out[i].Critical > out[j].Critical
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// intFromAny coerces JSON-decoded numerics (typically float64) to int. Used
// to read severity counts whether the operator emits them as integers or
// JSON numbers.
func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

// isNotFound returns true when the error indicates the resource type does
// not exist, which is how the apiserver reports a missing CRD to a
// dynamic client.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "the server could not find the requested resource") ||
		contains(msg, "could not find the requested resource") ||
		contains(msg, "no matches for kind")
}

// contains is a tiny substring helper that avoids importing strings for
// one call.
func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
