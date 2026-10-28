// Package crd enumerates the CustomResourceDefinitions installed on a
// cluster and surfaces per-cluster CRD divergence as a scanner result.
package crd

import (
	"context"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

// Info describes a single CustomResourceDefinition.
type Info struct {
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
	CRDs []Info `json:"crds"`
}

// NewScanner returns a scanner that lists CRDs in a cluster.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		dyn := client.Dynamic()
		if dyn == nil {
			return scanner.Result{Scanner: Name}, fmt.Errorf("%w: %s: dynamic client unavailable", scanner.ErrScan, Name)
		}

		var cov scanner.Coverage
		list, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), dyn.Resource(crdGVR).List,
			func(l *unstructured.UnstructuredList) []unstructured.Unstructured { return l.Items })
		if !cov.Observe("custom resource definitions", err) {
			list = nil
		}

		crds := make([]Info, 0, len(list))
		for _, item := range list {
			info := extractCRDInfo(item.Object)
			crds = append(crds, info)
		}
		sort.Slice(crds, func(i, j int) bool {
			return crds[i].Name < crds[j].Name
		})

		return cov.Finish(Name, Data{
			Count: len(crds),
			CRDs:  crds,
		})
	})
}

// extractCRDInfo pulls relevant fields from an unstructured CRD object.
func extractCRDInfo(obj map[string]any) Info {
	info := Info{}

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
