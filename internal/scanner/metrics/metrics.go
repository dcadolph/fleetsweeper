// Package metrics implements the scanner that reads node resource utilization from the
// metrics.k8s.io API.
package metrics

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "metrics"

// nodeMetricsGVR identifies the metrics.k8s.io NodeMetrics resource.
var nodeMetricsGVR = schema.GroupVersionResource{
	Group:    "metrics.k8s.io",
	Version:  "v1beta1",
	Resource: "nodes",
}

// NodeMetrics describes resource utilization for a single node.
type NodeMetrics struct {
	// Name is the node name.
	Name string `json:"name"`
	// CPUUsage is the current CPU usage (for example "250m").
	CPUUsage string `json:"cpu_usage"`
	// MemoryUsage is the current memory usage (for example "1.2Gi").
	MemoryUsage string `json:"memory_usage"`
	// CPUPercent is usage as a percentage of allocatable CPU (-1 if unknown).
	CPUPercent float64 `json:"cpu_percent"`
	// MemoryPercent is usage as a percentage of allocatable memory (-1 if unknown).
	MemoryPercent float64 `json:"memory_percent"`
}

// Data holds cluster-wide resource utilization metrics.
type Data struct {
	// Available is false when the cluster does not serve the metrics API.
	Available bool `json:"available"`
	// NodeCount is the number of nodes with metrics.
	NodeCount int `json:"node_count"`
	// AvgCPUPercent is the average CPU utilization across all nodes.
	AvgCPUPercent float64 `json:"avg_cpu_percent"`
	// AvgMemoryPercent is the average memory utilization across all nodes.
	AvgMemoryPercent float64 `json:"avg_memory_percent"`
	// MaxCPUPercent is the highest CPU utilization on any single node.
	MaxCPUPercent float64 `json:"max_cpu_percent"`
	// MaxMemoryPercent is the highest memory utilization on any single node.
	MaxMemoryPercent float64 `json:"max_memory_percent"`
	// MaxCPUNode is the name of the node with the highest CPU usage.
	MaxCPUNode string `json:"max_cpu_node,omitempty"`
	// MaxMemoryNode is the name of the node with the highest memory usage.
	MaxMemoryNode string `json:"max_memory_node,omitempty"`
	// Nodes lists per-node utilization metrics.
	Nodes []NodeMetrics `json:"nodes"`
}

// NewScanner returns a scanner that collects node resource utilization from the metrics API.
// A metrics API the cluster does not serve yields StateUnavailable. A denied or failed metrics
// read errors, so it is never mistaken for a healthy, zero-utilization cluster. A failed node
// read leaves usage without percentages and marks the result StateDegraded.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		dyn := client.Dynamic()
		if dyn == nil {
			return scanner.Result{Scanner: Name, State: scanner.StateErrored, Reason: "no dynamic client"},
				fmt.Errorf("%w: %s: no dynamic client", scanner.ErrScan, Name)
		}

		var cov scanner.Coverage
		metricsItems, err := scanner.ListAll(ctx, metav1.ListOptions{}, dyn.Resource(nodeMetricsGVR).List,
			func(l *unstructured.UnstructuredList) []unstructured.Unstructured { return l.Items })
		if !cov.Observe("node metrics", err) {
			return cov.Finish(Name, Data{Available: false})
		}

		nodes, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), client.Clientset().CoreV1().Nodes().List,
			func(l *corev1.NodeList) []corev1.Node { return l.Items })
		allocatable := make(map[string]allocInfo, len(nodes))
		if cov.Observe("nodes", err) {
			for _, n := range nodes {
				cpu := n.Status.Allocatable["cpu"]
				mem := n.Status.Allocatable["memory"]
				allocatable[n.Name] = allocInfo{
					cpuMilli: cpu.MilliValue(),
					memBytes: mem.Value(),
				}
			}
		}

		data := Data{
			Available: true,
			NodeCount: len(metricsItems),
		}

		var totalCPUPct, totalMemPct float64

		for _, item := range metricsItems {
			nm := extractNodeMetrics(item.Object, allocatable)
			data.Nodes = append(data.Nodes, nm)

			if nm.CPUPercent >= 0 {
				totalCPUPct += nm.CPUPercent
			}
			if nm.MemoryPercent >= 0 {
				totalMemPct += nm.MemoryPercent
			}
			if nm.CPUPercent > data.MaxCPUPercent {
				data.MaxCPUPercent = nm.CPUPercent
				data.MaxCPUNode = nm.Name
			}
			if nm.MemoryPercent > data.MaxMemoryPercent {
				data.MaxMemoryPercent = nm.MemoryPercent
				data.MaxMemoryNode = nm.Name
			}
		}

		if data.NodeCount > 0 {
			data.AvgCPUPercent = totalCPUPct / float64(data.NodeCount)
			data.AvgMemoryPercent = totalMemPct / float64(data.NodeCount)
		}

		sort.Slice(data.Nodes, func(i, j int) bool {
			return data.Nodes[i].Name < data.Nodes[j].Name
		})

		return cov.Finish(Name, data)
	})
}

// allocInfo captures the allocatable CPU (millicores) and memory (bytes) for
// one node, used to convert raw usage into percentages.
type allocInfo struct {
	// cpuMilli is allocatable CPU in millicores.
	cpuMilli int64
	// memBytes is allocatable memory in bytes.
	memBytes int64
}

// extractNodeMetrics pulls fields from an unstructured NodeMetrics object.
// CPU and memory quantities are parsed through k8s.io/apimachinery's
// resource.ParseQuantity so every Kubernetes quantity format (nanocores,
// millicores, decimal cores, Ki/Mi/Gi/Ti/Pi/Ei) is handled correctly.
func extractNodeMetrics(obj map[string]any, alloc map[string]allocInfo) NodeMetrics {
	nm := NodeMetrics{CPUPercent: -1, MemoryPercent: -1}

	if meta, ok := obj["metadata"].(map[string]any); ok {
		nm.Name, _ = meta["name"].(string)
	}

	usage, ok := obj["usage"].(map[string]any)
	if !ok {
		return nm
	}

	nm.CPUUsage, _ = usage["cpu"].(string)
	nm.MemoryUsage, _ = usage["memory"].(string)

	info, ok := alloc[nm.Name]
	if !ok || info.cpuMilli <= 0 || info.memBytes <= 0 {
		return nm
	}

	if q, err := resource.ParseQuantity(nm.CPUUsage); err == nil {
		used := q.MilliValue()
		if used > 0 {
			nm.CPUPercent = float64(used) / float64(info.cpuMilli) * 100
		}
	}
	if q, err := resource.ParseQuantity(nm.MemoryUsage); err == nil {
		used := q.Value()
		if used > 0 {
			nm.MemoryPercent = float64(used) / float64(info.memBytes) * 100
		}
	}

	return nm
}
