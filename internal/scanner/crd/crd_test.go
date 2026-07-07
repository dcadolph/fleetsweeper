package crd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// errBoom is a sentinel error injected into fake client reactors.
var errBoom = errors.New("boom")

// crdListKinds maps the CRD GVR to its list kind for the dynamic fake.
var crdListKinds = map[schema.GroupVersionResource]string{
	crdGVR: "CustomResourceDefinitionList",
}

// crdObject builds an unstructured CustomResourceDefinition for the dynamic
// fake. Each supplied version name becomes an entry under spec.versions.
func crdObject(name, group, scope string, versions ...string) *unstructured.Unstructured {
	vers := make([]any, 0, len(versions))
	for _, v := range versions {
		vers = append(vers, map[string]any{"name": v})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"group":    group,
			"scope":    scope,
			"versions": vers,
		},
	}}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantCRDs  []CRDInfo
		Objects   []*unstructured.Unstructured
		WantCount int
	}{{ // Test 0: No CRDs installed yields empty data.
		Objects:   nil,
		WantCount: 0,
		WantCRDs:  nil,
	}, { // Test 1: Multiple CRDs are extracted and sorted by name.
		Objects: []*unstructured.Unstructured{
			crdObject("widgets.example.com", "example.com", "Namespaced", "v1", "v1beta1"),
			crdObject("apples.example.com", "example.com", "Cluster", "v1"),
		},
		WantCount: 2,
		WantCRDs: []CRDInfo{
			{Name: "apples.example.com", Group: "example.com", Scope: "Cluster", Versions: []string{"v1"}},
			{
				Name:     "widgets.example.com",
				Group:    "example.com",
				Scope:    "Namespaced",
				Versions: []string{"v1", "v1beta1"},
			},
		},
	}, { // Test 2: A single cluster-scoped CRD declaring no versions.
		Objects:   []*unstructured.Unstructured{crdObject("clusters.infra.io", "infra.io", "Cluster")},
		WantCount: 1,
		WantCRDs: []CRDInfo{
			{Name: "clusters.infra.io", Group: "infra.io", Scope: "Cluster", Versions: nil},
		},
	}, { // Test 3: A CRD object missing its spec extracts only the name.
		Objects: []*unstructured.Unstructured{{Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata":   map[string]any{"name": "orphan.example.com"},
		}}},
		WantCount: 1,
		WantCRDs:  []CRDInfo{{Name: "orphan.example.com"}},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset()
			scheme := runtime.NewScheme()
			objs := make([]runtime.Object, 0, len(test.Objects))
			for _, o := range test.Objects {
				objs = append(objs, o)
			}
			dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, crdListKinds, objs...)
			client := kube.NewTestClientWithDynamic("test", cs, dyn)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}

			if diff := cmp.Diff(test.WantCount, data.Count); diff != "" {
				t.Errorf("count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCRDs, data.CRDs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("crds mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNewScannerNilDynamic verifies a nil dynamic client yields an errored
// result, since CRDs cannot be listed without it.
func TestNewScannerNilDynamic(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected error %v, got %v", scanner.ErrScan, err)
	}
}

// TestNewScannerListError verifies a CRD list failure propagates ErrScan
// instead of being swallowed as an empty result.
func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, crdListKinds)
	dyn.PrependReactor("list", "customresourcedefinitions",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errBoom
		})
	client := kube.NewTestClientWithDynamic("test", cs, dyn)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected error %v, got %v", scanner.ErrScan, err)
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped %v, got %v", errBoom, err)
	}
}
