package resources

import (
	"context"
	"fmt"
	"sort"


	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "resources"

// NodeInfo describes resource capacity and conditions for a single node.
type NodeInfo struct {
	// Name is the node name.
	Name string `json:"name"`
	// AllocatableCPU is the allocatable CPU in millicores.
	AllocatableCPU string `json:"allocatable_cpu"`
	// AllocatableMemory is the allocatable memory.
	AllocatableMemory string `json:"allocatable_memory"`
	// CapacityCPU is the total CPU capacity.
	CapacityCPU string `json:"capacity_cpu"`
	// CapacityMemory is the total memory capacity.
	CapacityMemory string `json:"capacity_memory"`
	// Conditions lists active conditions and their statuses.
	Conditions map[string]string `json:"conditions"`
	// Unschedulable is true when the node is cordoned.
	Unschedulable bool `json:"unschedulable"`
}

// Data holds resource information for one cluster.
type Data struct {
	// NodeCount is the total number of nodes.
	NodeCount int `json:"node_count"`
	// ReadyNodes is how many nodes report Ready=True.
	ReadyNodes int `json:"ready_nodes"`
	// UnschedulableNodes is how many are cordoned.
	UnschedulableNodes int `json:"unschedulable_nodes"`
	// TotalAllocatableCPU is the sum of allocatable CPU across all nodes.
	TotalAllocatableCPU string `json:"total_allocatable_cpu"`
	// TotalAllocatableMemory is the sum of allocatable memory across all nodes.
	TotalAllocatableMemory string `json:"total_allocatable_memory"`
	// Nodes lists per-node resource details.
	Nodes []NodeInfo `json:"nodes"`
}

// NewScanner returns a scanner that collects node resource and condition data.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		nodeList, err := client.Clientset().CoreV1().Nodes().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{NodeCount: len(nodeList.Items)}
		var totalCPUMilli int64
		var totalMemBytes int64

		for _, node := range nodeList.Items {
			conditions := make(map[string]string)
			for _, c := range node.Status.Conditions {
				conditions[string(c.Type)] = string(c.Status)
				if c.Type == "Ready" && c.Status == "True" {
					data.ReadyNodes++
				}
			}

			if node.Spec.Unschedulable {
				data.UnschedulableNodes++
			}

			allocCPU := node.Status.Allocatable["cpu"]
			allocMem := node.Status.Allocatable["memory"]
			capCPU := node.Status.Capacity["cpu"]
			capMem := node.Status.Capacity["memory"]

			totalCPUMilli += allocCPU.MilliValue()
			totalMemBytes += allocMem.Value()

			data.Nodes = append(data.Nodes, NodeInfo{
				Name:              node.Name,
				AllocatableCPU:    allocCPU.String(),
				AllocatableMemory: allocMem.String(),
				CapacityCPU:       capCPU.String(),
				CapacityMemory:    capMem.String(),
				Conditions:        conditions,
				Unschedulable:     node.Spec.Unschedulable,
			})
		}

		sort.Slice(data.Nodes, func(i, j int) bool {
			return data.Nodes[i].Name < data.Nodes[j].Name
		})

		data.TotalAllocatableCPU = fmt.Sprintf("%dm", totalCPUMilli)
		data.TotalAllocatableMemory = formatBytes(totalMemBytes)

		return scanner.Result{
			Scanner: Name,
			Data:    data,
		}, nil
	})
}

// formatBytes converts a byte count to a human-readable string.
func formatBytes(b int64) string {
	const gi = 1024 * 1024 * 1024
	if b >= gi {
		return fmt.Sprintf("%.1fGi", float64(b)/float64(gi))
	}
	const mi = 1024 * 1024
	return fmt.Sprintf("%.1fMi", float64(b)/float64(mi))
}
