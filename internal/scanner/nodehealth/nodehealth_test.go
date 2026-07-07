package nodehealth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// cond builds a node status condition with an empty reason and message.
func cond(condType corev1.NodeConditionType, status corev1.ConditionStatus) corev1.NodeCondition {
	return corev1.NodeCondition{Type: condType, Status: status}
}

// node builds a Node with the given name, cordon state, and conditions.
func node(name string, unschedulable bool, conds ...corev1.NodeCondition) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status:     corev1.NodeStatus{Conditions: conds},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name               string
		Objects            []runtime.Object
		WantNodes          []NodeHealth
		WantNodeNames      []string
		WantNodeCount      int
		WantHealthy        int
		WantUnhealthy      int
		WantMemoryPressure int
		WantDiskPressure   int
		WantPIDPressure    int
		WantNotReady       int
		WantUnschedulable  int
	}{{ // Test 0: Empty cluster has no nodes and no health data.
		Name:    "empty",
		Objects: nil,
	}, { // Test 1: Ready node with no pressure is healthy.
		Name: "healthy node",
		Objects: []runtime.Object{
			node("node-a", false,
				cond(corev1.NodeReady, corev1.ConditionTrue),
				cond(corev1.NodeMemoryPressure, corev1.ConditionFalse),
				cond(corev1.NodeDiskPressure, corev1.ConditionFalse),
				cond(corev1.NodePIDPressure, corev1.ConditionFalse),
			),
		},
		WantNodeCount: 1,
		WantHealthy:   1,
		WantNodes: []NodeHealth{{
			Name:  "node-a",
			Ready: true,
			Conditions: []NodeCondition{
				{Type: "Ready", Status: "True"},
				{Type: "MemoryPressure", Status: "False"},
				{Type: "DiskPressure", Status: "False"},
				{Type: "PIDPressure", Status: "False"},
			},
		}},
	}, { // Test 2: MemoryPressure marks an otherwise ready node unhealthy.
		Name: "memory pressure",
		Objects: []runtime.Object{
			node("node-a", false,
				cond(corev1.NodeReady, corev1.ConditionTrue),
				cond(corev1.NodeMemoryPressure, corev1.ConditionTrue),
			),
		},
		WantNodeCount:      1,
		WantUnhealthy:      1,
		WantMemoryPressure: 1,
	}, { // Test 3: Ready=False counts as not ready and unhealthy.
		Name: "not ready",
		Objects: []runtime.Object{
			node("node-a", false, cond(corev1.NodeReady, corev1.ConditionFalse)),
		},
		WantNodeCount: 1,
		WantUnhealthy: 1,
		WantNotReady:  1,
	}, { // Test 4: A node with no conditions defaults to not ready and unhealthy.
		Name:          "no conditions",
		Objects:       []runtime.Object{node("node-a", false)},
		WantNodeCount: 1,
		WantUnhealthy: 1,
		WantNotReady:  1,
		WantNodes:     []NodeHealth{{Name: "node-a"}},
	}, { // Test 5: A cordoned but ready node still counts as healthy.
		Name: "cordoned healthy",
		Objects: []runtime.Object{
			node("node-a", true, cond(corev1.NodeReady, corev1.ConditionTrue)),
		},
		WantNodeCount:     1,
		WantHealthy:       1,
		WantUnschedulable: 1,
		WantNodes: []NodeHealth{{
			Name:          "node-a",
			Ready:         true,
			Unschedulable: true,
			Conditions:    []NodeCondition{{Type: "Ready", Status: "True"}},
		}},
	}, { // Test 6: NetworkUnavailable marks a ready node unhealthy with no pressure counter.
		Name: "network unavailable",
		Objects: []runtime.Object{
			node("node-a", false,
				cond(corev1.NodeReady, corev1.ConditionTrue),
				cond(corev1.NodeNetworkUnavailable, corev1.ConditionTrue),
			),
		},
		WantNodeCount: 1,
		WantUnhealthy: 1,
	}, { // Test 7: Mixed cluster aggregates counts and sorts nodes by name.
		Name: "mixed cluster",
		Objects: []runtime.Object{
			node("node-c", false, cond(corev1.NodeReady, corev1.ConditionFalse)),
			node("node-a", false, cond(corev1.NodeReady, corev1.ConditionTrue)),
			node("node-b", false,
				cond(corev1.NodeReady, corev1.ConditionTrue),
				cond(corev1.NodeDiskPressure, corev1.ConditionTrue),
				cond(corev1.NodePIDPressure, corev1.ConditionTrue),
			),
		},
		WantNodeCount:    3,
		WantHealthy:      1,
		WantUnhealthy:    2,
		WantDiskPressure: 1,
		WantPIDPressure:  1,
		WantNotReady:     1,
		WantNodeNames:    []string{"node-a", "node-b", "node-c"},
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
			if diff := cmp.Diff(test.WantHealthy, data.HealthyNodes); diff != "" {
				t.Errorf("healthy nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantUnhealthy, data.UnhealthyNodes); diff != "" {
				t.Errorf("unhealthy nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantMemoryPressure, data.MemoryPressureNodes); diff != "" {
				t.Errorf("memory pressure nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDiskPressure, data.DiskPressureNodes); diff != "" {
				t.Errorf("disk pressure nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantPIDPressure, data.PIDPressureNodes); diff != "" {
				t.Errorf("pid pressure nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNotReady, data.NotReadyNodes); diff != "" {
				t.Errorf("not ready nodes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantUnschedulable, data.UnschedulableNodes); diff != "" {
				t.Errorf("unschedulable nodes mismatch (-want +got):\n%s", diff)
			}
			if test.WantNodes != nil {
				if diff := cmp.Diff(test.WantNodes, data.Nodes, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("nodes mismatch (-want +got):\n%s", diff)
				}
			}
			if test.WantNodeNames != nil {
				var names []string
				for _, n := range data.Nodes {
					names = append(names, n.Name)
				}
				if diff := cmp.Diff(test.WantNodeNames, names, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("node name order mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestNewScannerListError verifies the scanner wraps list failures with ErrScan.
func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected ErrScan, got %v", err)
	}
}
