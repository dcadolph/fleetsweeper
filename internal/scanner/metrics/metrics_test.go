package metrics

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// newMetricsDynamic returns a dynamic fake that serves the metrics.k8s.io
// NodeMetrics list kind, seeded with the supplied node metric objects.
// Objects are added under the explicit node-metrics GVR because the tracker's
// default kind-to-resource guess would pluralize "NodeMetrics" to
// "nodemetrics", which the scanner never queries.
func newMetricsDynamic(objs ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{nodeMetricsGVR: "NodeMetricsList"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
	for _, o := range objs {
		if err := dyn.Tracker().Create(nodeMetricsGVR, o, ""); err != nil {
			panic(err)
		}
	}
	return dyn
}

// nodeMetric builds an unstructured metrics.k8s.io/v1beta1 NodeMetrics object.
func nodeMetric(name, cpu, mem string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "metrics.k8s.io/v1beta1",
		"kind":       "NodeMetrics",
		"metadata":   map[string]any{"name": name},
		"usage":      map[string]any{"cpu": cpu, "memory": mem},
	}}
}

// allocNode builds a Node carrying allocatable CPU and memory quantities.
func allocNode(name, cpu, mem string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
			},
		},
	}
}

// nilDynamicClient returns a client with a typed clientset but no dynamic
// client, exercising the graceful unavailable path.
func nilDynamicClient() *kube.Client {
	return kube.NewTestClientWithClientset("test", fakeclientset.NewSimpleClientset())
}

// denyingClient returns a client whose dynamic node-metrics list fails with
// the supplied error, exercising the forbidden and generic-error branches.
func denyingClient(listErr error) *kube.Client {
	dyn := newMetricsDynamic()
	dyn.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, listErr
	})
	return kube.NewTestClientWithDynamic("test", fakeclientset.NewSimpleClientset(), dyn)
}

// TestExtractNodeMetrics checks quantity parsing and percentage math for the
// pure helper that converts one unstructured NodeMetrics object into a typed
// NodeMetrics, covering missing fields, missing allocatable data, unparseable
// quantities, zero usage, and several Kubernetes quantity formats.
func TestExtractNodeMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Obj         map[string]any
		Alloc       map[string]allocInfo
		WantMetrics NodeMetrics
	}{{ // Test 0: No metadata and no usage yields unknown percentages.
		Obj:         map[string]any{},
		WantMetrics: NodeMetrics{CPUPercent: -1, MemoryPercent: -1},
	}, { // Test 1: Metadata name present but no usage block.
		Obj:         map[string]any{"metadata": map[string]any{"name": "node-a"}},
		WantMetrics: NodeMetrics{Name: "node-a", CPUPercent: -1, MemoryPercent: -1},
	}, { // Test 2: Usage present but node missing from the allocatable map.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "250m", "memory": "1000Mi"},
		},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "250m", MemoryUsage: "1000Mi",
			CPUPercent: -1, MemoryPercent: -1,
		},
	}, { // Test 3: Allocatable present, percentages computed.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "250m", "memory": "1000Mi"},
		},
		Alloc: map[string]allocInfo{"node-a": {cpuMilli: 1000, memBytes: 2000 * 1024 * 1024}},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "250m", MemoryUsage: "1000Mi",
			CPUPercent: 25, MemoryPercent: 50,
		},
	}, { // Test 4: Zero allocatable capacity leaves percentages unknown.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "250m", "memory": "1000Mi"},
		},
		Alloc: map[string]allocInfo{"node-a": {cpuMilli: 0, memBytes: 0}},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "250m", MemoryUsage: "1000Mi",
			CPUPercent: -1, MemoryPercent: -1,
		},
	}, { // Test 5: Unparseable quantities leave percentages unknown.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "notaquantity", "memory": "alsobad"},
		},
		Alloc: map[string]allocInfo{"node-a": {cpuMilli: 1000, memBytes: 2000 * 1024 * 1024}},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "notaquantity", MemoryUsage: "alsobad",
			CPUPercent: -1, MemoryPercent: -1,
		},
	}, { // Test 6: Zero usage stays unknown because only positive usage counts.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "0", "memory": "0"},
		},
		Alloc: map[string]allocInfo{"node-a": {cpuMilli: 1000, memBytes: 2000 * 1024 * 1024}},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "0", MemoryUsage: "0",
			CPUPercent: -1, MemoryPercent: -1,
		},
	}, { // Test 7: Nanocore CPU and Gi memory formats parse correctly.
		Obj: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "500000000n", "memory": "1Gi"},
		},
		Alloc: map[string]allocInfo{"node-a": {cpuMilli: 1000, memBytes: 2 * 1024 * 1024 * 1024}},
		WantMetrics: NodeMetrics{
			Name: "node-a", CPUUsage: "500000000n", MemoryUsage: "1Gi",
			CPUPercent: 50, MemoryPercent: 50,
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := extractNodeMetrics(test.Obj, test.Alloc)
			if diff := cmp.Diff(test.WantMetrics, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestScan drives the full metrics scanner over the dynamic and typed fakes,
// covering the missing dynamic client, a missing metrics API (NoMatch and
// NotFound), a 403, a generic list error, the resolved-percentage
// aggregation, and metrics without matching nodes.
func TestScan(t *testing.T) {
	t.Parallel()

	errDenied := errors.New("rbac denied")
	errBoom := errors.New("boom")

	tests := []struct {
		Client    *kube.Client
		Want      error
		WantState scanner.State
		WantData  Data
	}{{ // Test 0: No dynamic client means metrics are unavailable.
		Client:   nilDynamicClient(),
		WantData: Data{Available: false},
	}, { // Test 1: A NoMatch error means the metrics API is absent, not a failure.
		Client: denyingClient(&meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{
			Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes",
		}}),
		WantState: scanner.StateUnavailable,
		WantData:  Data{Available: false},
	}, { // Test 2: A NotFound error also means the metrics API is absent.
		Client: denyingClient(apierrors.NewNotFound(
			schema.GroupResource{Group: "metrics.k8s.io", Resource: "nodes"}, "")),
		WantState: scanner.StateUnavailable,
		WantData:  Data{Available: false},
	}, { // Test 3: A 403 is a blind read: the error propagates with the RBAC flag set.
		Client: denyingClient(apierrors.NewForbidden(
			schema.GroupResource{Group: "metrics.k8s.io", Resource: "nodes"}, "", errDenied)),
		Want:     scanner.ErrScan,
		WantData: Data{Available: false, Forbidden: true},
	}, { // Test 4: A non-403 error is a blind read and propagates as an error.
		Client: denyingClient(errBoom),
		Want:   scanner.ErrScan,
	}, { // Test 5: Metrics resolve against allocatable node capacity.
		Client: kube.NewTestClientWithDynamic("test",
			fakeclientset.NewSimpleClientset(
				allocNode("node1", "1", "2000Mi"),
				allocNode("node2", "2", "4000Mi"),
			),
			newMetricsDynamic(
				nodeMetric("node1", "250m", "1000Mi"),
				nodeMetric("node2", "1000m", "1000Mi"),
			),
		),
		WantData: Data{
			Available: true, NodeCount: 2,
			AvgCPUPercent: 37.5, AvgMemoryPercent: 37.5,
			MaxCPUPercent: 50, MaxCPUNode: "node2",
			MaxMemoryPercent: 50, MaxMemoryNode: "node1",
			Nodes: []NodeMetrics{
				{Name: "node1", CPUUsage: "250m", MemoryUsage: "1000Mi", CPUPercent: 25, MemoryPercent: 50},
				{Name: "node2", CPUUsage: "1000m", MemoryUsage: "1000Mi", CPUPercent: 50, MemoryPercent: 25},
			},
		},
	}, { // Test 6: Metrics without matching nodes stay unresolved but available.
		Client: kube.NewTestClientWithDynamic("test",
			fakeclientset.NewSimpleClientset(),
			newMetricsDynamic(nodeMetric("orphan", "250m", "100Mi")),
		),
		WantData: Data{
			Available: true, NodeCount: 1,
			Nodes: []NodeMetrics{
				{Name: "orphan", CPUUsage: "250m", MemoryUsage: "100Mi", CPUPercent: -1, MemoryPercent: -1},
			},
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			result, err := NewScanner().Scan(context.Background(), test.Client)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: want %v, got %v", test.Want, err)
			}
			if diff := cmp.Diff(Name, result.Scanner); diff != "" {
				t.Errorf("scanner name mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantState, result.State); diff != "" {
				t.Errorf("state mismatch (-want +got):\n%s", diff)
			}
			if result.Data == nil {
				return
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			opts := cmp.Options{cmpopts.EquateApprox(0, 1e-9), cmpopts.EquateEmpty()}
			if diff := cmp.Diff(test.WantData, data, opts); diff != "" {
				t.Errorf("data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
