package metrics

import (
	"context"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// Available is false when metrics-server is not installed or not authorized.
	Available bool `json:"available"`
	// Forbidden is true when the API returned 403 (metrics-server installed but
	// RBAC denied). Distinguishing this from "not installed" lets operators fix
	// the right thing.
	Forbidden bool `json:"forbidden,omitempty"`
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

// NewScanner returns a scanner that collects node resource utilization from
// the metrics API. Returns Available=false with Forbidden=true on 403 so
// operators know whether to install metrics-server or fix RBAC.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		dyn := client.Dynamic()
		if dyn == nil {
			return scanner.Result{Scanner: Name, Data: Data{Available: false}}, nil
		}

		metricsList, err := dyn.Resource(nodeMetricsGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			if errors.IsForbidden(err) {
				return scanner.Result{Scanner: Name, Data: Data{Available: false, Forbidden: true}}, nil
			}
			return scanner.Result{Scanner: Name, Data: Data{Available: false}}, nil
		}

		nodeList, nodeErr := client.Clientset().CoreV1().Nodes().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		allocatable := make(map[string]allocInfo)
		if nodeErr == nil {
			for _, n := range nodeList.Items {
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
			NodeCount: len(metricsList.Items),
		}

		var totalCPUPct, totalMemPct float64

		for _, item := range metricsList.Items {
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

		return scanner.Result{
			Scanner: Name,
			Data:    data,
		}, nil
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
