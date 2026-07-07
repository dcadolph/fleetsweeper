package resources

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// errBoom is a sentinel error injected into fake client reactors.
var errBoom = errors.New("boom")

// node builds a Node with the given CPU and memory, readiness, and cordon state.
// Allocatable and capacity are set to the same values for simplicity.
func node(name, cpu, mem string, ready, unschedulable bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	list := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(cpu),
		corev1.ResourceMemory: resource.MustParse(mem),
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{
			Allocatable: list,
			Capacity:    list,
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name                       string
		WantTotalAllocatableCPU    string
		WantTotalAllocatableMemory string
		WantFirstNodeName          string
		WantFirstAllocatableCPU    string
		WantFirstAllocatableMemory string
		WantFirstConditions        map[string]string
		Objects                    []runtime.Object
		WantNodeCount              int
		WantReadyNodes             int
		WantUnschedulableNodes     int
		WantFirstUnschedulable     bool
	}{{ // Test 0: Empty cluster reports zero nodes and zero totals.
		Name:                       "empty",
		Objects:                    nil,
		WantNodeCount:              0,
		WantReadyNodes:             0,
		WantUnschedulableNodes:     0,
		WantTotalAllocatableCPU:    "0m",
		WantTotalAllocatableMemory: "0.0Mi",
	}, { // Test 1: Two ready nodes, one cordoned, totals sum across both.
		Name: "two ready one cordoned",
		Objects: []runtime.Object{
			node("node-b", "2", "1Gi", true, true),
			node("node-a", "2", "1Gi", true, false),
		},
		WantNodeCount:              2,
		WantReadyNodes:             2,
		WantUnschedulableNodes:     1,
		WantTotalAllocatableCPU:    "4000m",
		WantTotalAllocatableMemory: "2.0Gi",
		WantFirstNodeName:          "node-a",
		WantFirstAllocatableCPU:    "2",
		WantFirstAllocatableMemory: "1Gi",
		WantFirstConditions:        map[string]string{"Ready": "True"},
		WantFirstUnschedulable:     false,
	}, { // Test 2: Single not-ready node with sub-core CPU and mebibyte memory.
		Name: "single not ready",
		Objects: []runtime.Object{
			node("node-x", "500m", "512Mi", false, false),
		},
		WantNodeCount:              1,
		WantReadyNodes:             0,
		WantUnschedulableNodes:     0,
		WantTotalAllocatableCPU:    "500m",
		WantTotalAllocatableMemory: "512.0Mi",
		WantFirstNodeName:          "node-x",
		WantFirstAllocatableCPU:    "500m",
		WantFirstAllocatableMemory: "512Mi",
		WantFirstConditions:        map[string]string{"Ready": "False"},
		WantFirstUnschedulable:     false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset(test.Objects...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}

			if diff := cmp.Diff(test.WantNodeCount, data.NodeCount); diff != "" {
				t.Errorf("node count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantReadyNodes, data.ReadyNodes); diff != "" {
				t.Errorf("ready nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantUnschedulableNodes, data.UnschedulableNodes); diff != "" {
				t.Errorf("unschedulable nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantTotalAllocatableCPU, data.TotalAllocatableCPU); diff != "" {
				t.Errorf("total allocatable cpu mismatch (-want +got):\n%s", diff)
			}
			got := data.TotalAllocatableMemory
			if diff := cmp.Diff(test.WantTotalAllocatableMemory, got); diff != "" {
				t.Errorf("total allocatable memory mismatch (-want +got):\n%s", diff)
			}
			if test.WantFirstNodeName == "" {
				return
			}
			if len(data.Nodes) == 0 {
				t.Fatal("expected at least one node")
			}
			first := data.Nodes[0]
			if diff := cmp.Diff(test.WantFirstNodeName, first.Name); diff != "" {
				t.Errorf("first node name mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstAllocatableCPU, first.AllocatableCPU); diff != "" {
				t.Errorf("first node allocatable cpu mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstAllocatableMemory, first.AllocatableMemory); diff != "" {
				t.Errorf("first node allocatable memory mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstConditions, first.Conditions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("first node conditions mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstUnschedulable, first.Unschedulable); diff != "" {
				t.Errorf("first node unschedulable mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errBoom
		})
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected error %v, got %v", scanner.ErrScan, err)
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped %v, got %v", errBoom, err)
	}
}
