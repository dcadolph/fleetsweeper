package clusterinfo

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
)

// node builds a Node whose status.nodeInfo carries the given platform strings.
func node(name, osImage, kernel, runtimeVer, kubelet, kubeProxy string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OSImage:                 osImage,
				KernelVersion:           kernel,
				ContainerRuntimeVersion: runtimeVer,
				KubeletVersion:          kubelet,
				KubeProxyVersion:        kubeProxy,
			},
		},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name                string
		Objects             []runtime.Object
		WantNodes           []NodeInfo
		WantOSImages        []string
		WantKernelVersions  []string
		WantRuntimeVersions []string
		WantKubeletVersions []string
		WantNodeNames       []string
		WantNodeCount       int
		WantHasDrift        bool
	}{{ // Test 0: Empty cluster has no nodes and no drift.
		Name: "empty",
	}, { // Test 1: Uniform nodes report one value per dimension and no drift.
		Name: "uniform nodes",
		Objects: []runtime.Object{
			node("node-a", "Ubuntu 22.04", "5.15.0", "containerd://1.7.0", "v1.30.0", "v1.30.0"),
			node("node-b", "Ubuntu 22.04", "5.15.0", "containerd://1.7.0", "v1.30.0", "v1.30.0"),
		},
		WantNodeCount:       2,
		WantOSImages:        []string{"Ubuntu 22.04"},
		WantKernelVersions:  []string{"5.15.0"},
		WantRuntimeVersions: []string{"containerd://1.7.0"},
		WantKubeletVersions: []string{"v1.30.0"},
		WantNodeNames:       []string{"node-a", "node-b"},
		WantNodes: []NodeInfo{{
			Name: "node-a", OSImage: "Ubuntu 22.04", KernelVersion: "5.15.0",
			ContainerRuntimeVersion: "containerd://1.7.0",
			KubeletVersion:          "v1.30.0", KubeProxyVersion: "v1.30.0",
		}, {
			Name: "node-b", OSImage: "Ubuntu 22.04", KernelVersion: "5.15.0",
			ContainerRuntimeVersion: "containerd://1.7.0",
			KubeletVersion:          "v1.30.0", KubeProxyVersion: "v1.30.0",
		}},
	}, { // Test 2: Differing kubelet versions flag drift.
		Name: "kubelet drift",
		Objects: []runtime.Object{
			node("node-a", "Ubuntu 22.04", "5.15.0", "containerd://1.7.0", "v1.29.0", "v1.29.0"),
			node("node-b", "Ubuntu 22.04", "5.15.0", "containerd://1.7.0", "v1.30.0", "v1.30.0"),
		},
		WantNodeCount:       2,
		WantOSImages:        []string{"Ubuntu 22.04"},
		WantKernelVersions:  []string{"5.15.0"},
		WantRuntimeVersions: []string{"containerd://1.7.0"},
		WantKubeletVersions: []string{"v1.29.0", "v1.30.0"},
		WantNodeNames:       []string{"node-a", "node-b"},
		WantHasDrift:        true,
	}, { // Test 3: Differing OS images flag drift and sort alphabetically.
		Name: "os drift",
		Objects: []runtime.Object{
			node("node-b", "Ubuntu 22.04", "5.15.0", "containerd://1.7.0", "v1.30.0", "v1.30.0"),
			node("node-a", "Amazon Linux 2", "5.15.0", "containerd://1.7.0", "v1.30.0", "v1.30.0"),
		},
		WantNodeCount:       2,
		WantOSImages:        []string{"Amazon Linux 2", "Ubuntu 22.04"},
		WantKernelVersions:  []string{"5.15.0"},
		WantRuntimeVersions: []string{"containerd://1.7.0"},
		WantKubeletVersions: []string{"v1.30.0"},
		WantNodeNames:       []string{"node-a", "node-b"},
		WantHasDrift:        true,
	}, { // Test 4: Empty platform strings are omitted from the distinct lists.
		Name:          "empty platform fields",
		Objects:       []runtime.Object{node("node-a", "", "", "", "", "")},
		WantNodeCount: 1,
		WantNodeNames: []string{"node-a"},
		WantNodes:     []NodeInfo{{Name: "node-a"}},
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
			if diff := cmp.Diff(test.WantHasDrift, data.HasDrift); diff != "" {
				t.Errorf("has drift mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantOSImages, data.OSImages, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("os images mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantKernelVersions, data.KernelVersions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("kernel versions mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantRuntimeVersions, data.RuntimeVersions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("runtime versions mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantKubeletVersions, data.KubeletVersions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("kubelet versions mismatch (-want +got):\n%s", diff)
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
			if test.WantNodes != nil {
				if diff := cmp.Diff(test.WantNodes, data.Nodes, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("nodes mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestNewScannerListError verifies a list failure yields empty data and no error.
func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}
	if diff := cmp.Diff(Data{}, data, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("expected empty data (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(Name, result.Scanner); diff != "" {
		t.Errorf("scanner name mismatch (-want +got):\n%s", diff)
	}
}
