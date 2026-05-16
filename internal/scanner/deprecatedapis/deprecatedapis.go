// Package deprecatedapis identifies in-use API versions that Kubernetes has
// deprecated or removed. It walks the discovery API for every server-known
// group/version and cross-references against an embedded removal table. The
// table covers the most operationally impactful deprecations through 1.33.
// Operators rarely upgrade with confidence; this scanner answers "what will
// break in the next release?" in one place.
package deprecatedapis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "deprecated-apis"

// deprecation describes one deprecated/removed API version. RemovedIn is the
// first Kubernetes minor version where the API stopped being served.
type deprecation struct {
	// Group is the API group, empty for core/v1.
	Group string
	// Version is the deprecated version string (for example "v1beta1").
	Version string
	// Kind is the resource Kind.
	Kind string
	// Replacement is the suggested replacement apiVersion/kind.
	Replacement string
	// RemovedIn is the Kubernetes minor version that removed this API.
	RemovedIn string
}

// removals enumerates the operationally important deprecations. Newer entries
// can be appended without breaking older scans. This is intentionally curated
// rather than exhaustive: every entry here costs nothing to evaluate, while
// random alpha groups would create noise.
var removals = []deprecation{
	{Group: "extensions", Version: "v1beta1", Kind: "Ingress", Replacement: "networking.k8s.io/v1 Ingress", RemovedIn: "1.22"},
	{Group: "networking.k8s.io", Version: "v1beta1", Kind: "Ingress", Replacement: "networking.k8s.io/v1 Ingress", RemovedIn: "1.22"},
	{Group: "extensions", Version: "v1beta1", Kind: "PodSecurityPolicy", Replacement: "PodSecurity admission (PSS)", RemovedIn: "1.25"},
	{Group: "policy", Version: "v1beta1", Kind: "PodSecurityPolicy", Replacement: "PodSecurity admission (PSS)", RemovedIn: "1.25"},
	{Group: "policy", Version: "v1beta1", Kind: "PodDisruptionBudget", Replacement: "policy/v1 PodDisruptionBudget", RemovedIn: "1.25"},
	{Group: "batch", Version: "v1beta1", Kind: "CronJob", Replacement: "batch/v1 CronJob", RemovedIn: "1.25"},
	{Group: "discovery.k8s.io", Version: "v1beta1", Kind: "EndpointSlice", Replacement: "discovery.k8s.io/v1 EndpointSlice", RemovedIn: "1.25"},
	{Group: "events.k8s.io", Version: "v1beta1", Kind: "Event", Replacement: "events.k8s.io/v1 Event", RemovedIn: "1.25"},
	{Group: "autoscaling", Version: "v2beta1", Kind: "HorizontalPodAutoscaler", Replacement: "autoscaling/v2 HorizontalPodAutoscaler", RemovedIn: "1.25"},
	{Group: "autoscaling", Version: "v2beta2", Kind: "HorizontalPodAutoscaler", Replacement: "autoscaling/v2 HorizontalPodAutoscaler", RemovedIn: "1.26"},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Kind: "FlowSchema", Replacement: "flowcontrol.apiserver.k8s.io/v1 FlowSchema", RemovedIn: "1.26"},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Kind: "FlowSchema", Replacement: "flowcontrol.apiserver.k8s.io/v1 FlowSchema", RemovedIn: "1.29"},
	{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity", Replacement: "storage.k8s.io/v1 CSIStorageCapacity", RemovedIn: "1.27"},
	{Group: "node.k8s.io", Version: "v1beta1", Kind: "RuntimeClass", Replacement: "node.k8s.io/v1 RuntimeClass", RemovedIn: "1.25"},
	{Group: "admissionregistration.k8s.io", Version: "v1beta1", Kind: "MutatingWebhookConfiguration", Replacement: "admissionregistration.k8s.io/v1 MutatingWebhookConfiguration", RemovedIn: "1.22"},
	{Group: "admissionregistration.k8s.io", Version: "v1beta1", Kind: "ValidatingWebhookConfiguration", Replacement: "admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration", RemovedIn: "1.22"},
	{Group: "rbac.authorization.k8s.io", Version: "v1beta1", Kind: "Role", Replacement: "rbac.authorization.k8s.io/v1 Role", RemovedIn: "1.22"},
	{Group: "apiextensions.k8s.io", Version: "v1beta1", Kind: "CustomResourceDefinition", Replacement: "apiextensions.k8s.io/v1 CustomResourceDefinition", RemovedIn: "1.22"},
}

// Deprecated describes one in-use deprecated API instance with location.
type Deprecated struct {
	// APIVersion is the deprecated apiVersion.
	APIVersion string `json:"api_version"`
	// Kind is the resource Kind.
	Kind string `json:"kind"`
	// Replacement is the suggested replacement.
	Replacement string `json:"replacement"`
	// RemovedIn is the Kubernetes minor version that removed the API.
	RemovedIn string `json:"removed_in"`
	// InstanceCount is the number of objects observed at this apiVersion.
	InstanceCount int `json:"instance_count"`
	// Forbidden is true when the API server returned 403 for the list call
	// (meaning we cannot count instances even though the resource is served).
	Forbidden bool `json:"forbidden,omitempty"`
}

// Data holds deprecated API findings for one cluster.
type Data struct {
	// ServerVersion is the cluster's reported minor version, when known.
	ServerVersion string `json:"server_version,omitempty"`
	// Deprecated lists deprecated APIs that are still being served and used.
	Deprecated []Deprecated `json:"deprecated"`
	// TotalInstances is the sum of InstanceCount across all entries.
	TotalInstances int `json:"total_instances"`
}

// NewScanner returns a scanner that identifies deprecated API usage in the
// cluster. Each removal candidate is checked by listing instances at the
// deprecated version; only versions still served by the apiserver and with at
// least one instance are reported.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		data := Data{}

		if info, err := client.Clientset().Discovery().ServerVersion(); err == nil {
			data.ServerVersion = info.GitVersion
		}

		dyn := client.Dynamic()
		if dyn == nil {
			return scanner.Result{Scanner: Name, Data: data}, nil
		}

		discovery := client.Clientset().Discovery()
		serverGroups, err := discovery.ServerGroups()
		served := make(map[string]bool)
		if err == nil {
			for _, g := range serverGroups.Groups {
				for _, v := range g.Versions {
					served[fmt.Sprintf("%s/%s", g.Name, v.Version)] = true
				}
			}
		}

		for _, rm := range removals {
			gv := rm.Version
			gvKey := rm.Version
			if rm.Group != "" {
				gv = rm.Group + "/" + rm.Version
				gvKey = gv
			}
			if !served[gvKey] && !(rm.Group == "" && served["v1"]) {
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    rm.Group,
				Version:  rm.Version,
				Resource: lowercasePlural(rm.Kind),
			}
			list, listErr := dyn.Resource(gvr).List(ctx, metav1.ListOptions{
				Limit:                1000,
				ResourceVersion:      "0",
				ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
			})
			entry := Deprecated{
				APIVersion:  gv,
				Kind:        rm.Kind,
				Replacement: rm.Replacement,
				RemovedIn:   rm.RemovedIn,
			}
			if listErr != nil {
				if errors.IsNotFound(listErr) || errors.IsMethodNotSupported(listErr) {
					continue
				}
				if errors.IsForbidden(listErr) {
					entry.Forbidden = true
					data.Deprecated = append(data.Deprecated, entry)
				}
				continue
			}
			if list == nil || len(list.Items) == 0 {
				continue
			}
			entry.InstanceCount = len(list.Items)
			data.Deprecated = append(data.Deprecated, entry)
			data.TotalInstances += entry.InstanceCount
		}

		sort.Slice(data.Deprecated, func(i, j int) bool {
			if data.Deprecated[i].RemovedIn != data.Deprecated[j].RemovedIn {
				return data.Deprecated[i].RemovedIn < data.Deprecated[j].RemovedIn
			}
			return data.Deprecated[i].APIVersion < data.Deprecated[j].APIVersion
		})

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// lowercasePlural converts a Kind name to its conventional resource plural.
// Kubernetes resource names are lowercased plurals of the Kind; the rules
// here cover the resources in the removals table without needing the full
// discovery REST mapper at every call.
func lowercasePlural(kind string) string {
	s := strings.ToLower(kind)
	switch {
	case strings.HasSuffix(s, "s"):
		return s + "es"
	case strings.HasSuffix(s, "y"):
		return strings.TrimSuffix(s, "y") + "ies"
	default:
		return s + "s"
	}
}
