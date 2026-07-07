// Package clusterinfo collects node OS, kernel, container runtime, kubelet
// and kube-proxy versions and reports drift within a single cluster. The
// fleet comparison naturally surfaces drift across clusters; this scanner
// surfaces it inside a cluster, which is where mid-upgrade and rolling-AMI
// issues hide.
package clusterinfo

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "cluster-info"

// NodeInfo describes the platform identity of a single node.
type NodeInfo struct {
	// Name is the node name.
	Name string `json:"name"`
	// OSImage is the OS image identifier from node.status.nodeInfo.
	OSImage string `json:"os_image"`
	// KernelVersion is the kernel version string.
	KernelVersion string `json:"kernel_version"`
	// ContainerRuntimeVersion is the runtime + version (for example "containerd://1.7").
	ContainerRuntimeVersion string `json:"container_runtime_version"`
	// KubeletVersion is the kubelet version reported by the node.
	KubeletVersion string `json:"kubelet_version"`
	// KubeProxyVersion is the kube-proxy version reported by the node.
	KubeProxyVersion string `json:"kube_proxy_version"`
}

// Data holds platform drift information for one cluster.
type Data struct {
	// NodeCount is the number of nodes inspected.
	NodeCount int `json:"node_count"`
	// OSImages lists distinct OS images across the cluster.
	OSImages []string `json:"os_images"`
	// KernelVersions lists distinct kernel versions across the cluster.
	KernelVersions []string `json:"kernel_versions"`
	// RuntimeVersions lists distinct container runtimes across the cluster.
	RuntimeVersions []string `json:"runtime_versions"`
	// KubeletVersions lists distinct kubelet versions across the cluster.
	KubeletVersions []string `json:"kubelet_versions"`
	// HasDrift is true when any of the above lists has more than one entry.
	HasDrift bool `json:"has_drift"`
	// Nodes is the per-node detail, capped at 200 entries.
	Nodes []NodeInfo `json:"nodes"`
}

// NewScanner returns a scanner that aggregates platform identity for every
// node in the cluster and exposes intra-cluster drift.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		list, err := client.Clientset().CoreV1().Nodes().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err != nil {
			return scanner.Result{Scanner: Name}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}
		data := Data{NodeCount: len(list.Items)}
		os := uniqueStringSet{}
		kernel := uniqueStringSet{}
		runtime := uniqueStringSet{}
		kubelet := uniqueStringSet{}

		for i := range list.Items {
			n := &list.Items[i]
			info := n.Status.NodeInfo
			os.add(info.OSImage)
			kernel.add(info.KernelVersion)
			runtime.add(info.ContainerRuntimeVersion)
			kubelet.add(info.KubeletVersion)
			data.Nodes = append(data.Nodes, NodeInfo{
				Name:                    n.Name,
				OSImage:                 info.OSImage,
				KernelVersion:           info.KernelVersion,
				ContainerRuntimeVersion: info.ContainerRuntimeVersion,
				KubeletVersion:          info.KubeletVersion,
				KubeProxyVersion:        info.KubeProxyVersion,
			})
		}

		data.OSImages = os.sortedSlice()
		data.KernelVersions = kernel.sortedSlice()
		data.RuntimeVersions = runtime.sortedSlice()
		data.KubeletVersions = kubelet.sortedSlice()
		data.HasDrift = len(data.OSImages) > 1 || len(data.KernelVersions) > 1 || len(data.RuntimeVersions) > 1 || len(data.KubeletVersions) > 1

		sort.Slice(data.Nodes, func(i, j int) bool {
			return data.Nodes[i].Name < data.Nodes[j].Name
		})
		if len(data.Nodes) > 200 {
			data.Nodes = data.Nodes[:200]
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// uniqueStringSet collects distinct non-empty strings and returns them sorted.
type uniqueStringSet map[string]struct{}

// add records a string in the set, ignoring empty values so missing fields
// don't pollute the output with blanks.
func (s uniqueStringSet) add(v string) {
	if v == "" {
		return
	}
	s[v] = struct{}{}
}

// sortedSlice returns the set's contents as a sorted []string.
func (s uniqueStringSet) sortedSlice() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
