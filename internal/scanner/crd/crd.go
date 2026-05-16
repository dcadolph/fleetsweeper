package crd

import (
	"context"
	"sort"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "crds"

var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}

// CRDInfo describes a single CustomResourceDefinition.
type CRDInfo struct {
	// Name is the CRD name (e.g. certificates.cert-manager.io).
	Name string `json:"name"`
	// Group is the API group.
	Group string `json:"group"`
	// Versions lists the served version names.
	Versions []string `json:"versions"`
	// Scope is Namespaced or Cluster.
	Scope string `json:"scope"`
}

// Data holds CRD information for one cluster.
type Data struct {
	// Count is the total number of CRDs.
	Count int `json:"count"`
	// CRDs lists all CustomResourceDefinitions.
	CRDs []CRDInfo `json:"crds"`
}

// NewScanner returns a scanner that lists CRDs in a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		dyn := client.Dynamic()
		if dyn == nil {
			return scanner.Result{Scanner: Name, Data: Data{}}, nil
		}

		list, err := dyn.Resource(crdGVR).List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{Scanner: Name, Data: Data{}}, nil //nolint:nilerr // CRD API may not be available.
		}

		crds := make([]CRDInfo, 0, len(list.Items))
		for _, item := range list.Items {
			info := extractCRDInfo(item.Object)
			crds = append(crds, info)
		}
		sort.Slice(crds, func(i, j int) bool {
			return crds[i].Name < crds[j].Name
		})

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Count: len(crds),
				CRDs:  crds,
			},
		}, nil
	})
}

// extractCRDInfo pulls relevant fields from an unstructured CRD object.
func extractCRDInfo(obj map[string]any) CRDInfo {
	info := CRDInfo{}

	if meta, ok := obj["metadata"].(map[string]any); ok {
		info.Name, _ = meta["name"].(string)
	}

	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return info
	}

	info.Group, _ = spec["group"].(string)
	info.Scope, _ = spec["scope"].(string)

	if versions, ok := spec["versions"].([]any); ok {
		for _, v := range versions {
			if vm, ok := v.(map[string]any); ok {
				if name, ok := vm["name"].(string); ok {
					info.Versions = append(info.Versions, name)
				}
			}
		}
	}

	return info
}

// DynamicLister is satisfied by dynamic.Interface for testing.
type DynamicLister interface {
	Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface
}
