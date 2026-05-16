package nodehealth

import (
	"context"
	"fmt"
	"sort"


	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "node-health"

// NodeCondition describes a condition on a single node.
type NodeCondition struct {
	// Type is the condition type (Ready, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable).
	Type string `json:"type"`
	// Status is True, False, or Unknown.
	Status string `json:"status"`
	// Reason is the machine-readable reason string.
	Reason string `json:"reason,omitempty"`
	// Message is the human-readable message.
	Message string `json:"message,omitempty"`
}

// NodeHealth describes the health posture of a single node.
type NodeHealth struct {
	// Name is the node name.
	Name string `json:"name"`
	// Ready is true when the node reports Ready=True.
	Ready bool `json:"ready"`
	// MemoryPressure is true when the node reports MemoryPressure=True.
	MemoryPressure bool `json:"memory_pressure"`
	// DiskPressure is true when the node reports DiskPressure=True.
	DiskPressure bool `json:"disk_pressure"`
	// PIDPressure is true when the node reports PIDPressure=True.
	PIDPressure bool `json:"pid_pressure"`
	// NetworkUnavailable is true when the node reports NetworkUnavailable=True.
	NetworkUnavailable bool `json:"network_unavailable"`
	// Unschedulable is true when the node is cordoned.
	Unschedulable bool `json:"unschedulable"`
	// Conditions lists all conditions for detailed inspection.
	Conditions []NodeCondition `json:"conditions"`
}

// Data holds node health information for one cluster.
type Data struct {
	// NodeCount is the total number of nodes.
	NodeCount int `json:"node_count"`
	// HealthyNodes is how many nodes are Ready with no pressure conditions.
	HealthyNodes int `json:"healthy_nodes"`
	// UnhealthyNodes is how many nodes have at least one pressure condition or are not ready.
	UnhealthyNodes int `json:"unhealthy_nodes"`
	// MemoryPressureNodes is how many nodes report MemoryPressure=True.
	MemoryPressureNodes int `json:"memory_pressure_nodes"`
	// DiskPressureNodes is how many nodes report DiskPressure=True.
	DiskPressureNodes int `json:"disk_pressure_nodes"`
	// PIDPressureNodes is how many nodes report PIDPressure=True.
	PIDPressureNodes int `json:"pid_pressure_nodes"`
	// NotReadyNodes is how many nodes report Ready!=True.
	NotReadyNodes int `json:"not_ready_nodes"`
	// UnschedulableNodes is how many nodes are cordoned.
	UnschedulableNodes int `json:"unschedulable_nodes"`
	// Nodes lists per-node health details.
	Nodes []NodeHealth `json:"nodes"`
}

// NewScanner returns a scanner that checks node health conditions.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		nodeList, err := client.Clientset().CoreV1().Nodes().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{NodeCount: len(nodeList.Items)}

		for _, node := range nodeList.Items {
			nh := NodeHealth{
				Name:          node.Name,
				Unschedulable: node.Spec.Unschedulable,
			}

			for _, c := range node.Status.Conditions {
				nh.Conditions = append(nh.Conditions, NodeCondition{
					Type:    string(c.Type),
					Status:  string(c.Status),
					Reason:  c.Reason,
					Message: c.Message,
				})
				isTrue := c.Status == "True"
				switch string(c.Type) {
				case "Ready":
					nh.Ready = isTrue
				case "MemoryPressure":
					nh.MemoryPressure = isTrue
				case "DiskPressure":
					nh.DiskPressure = isTrue
				case "PIDPressure":
					nh.PIDPressure = isTrue
				case "NetworkUnavailable":
					nh.NetworkUnavailable = isTrue
				}
			}

			if node.Spec.Unschedulable {
				data.UnschedulableNodes++
			}
			if !nh.Ready {
				data.NotReadyNodes++
			}
			if nh.MemoryPressure {
				data.MemoryPressureNodes++
			}
			if nh.DiskPressure {
				data.DiskPressureNodes++
			}
			if nh.PIDPressure {
				data.PIDPressureNodes++
			}

			healthy := nh.Ready && !nh.MemoryPressure && !nh.DiskPressure && !nh.PIDPressure && !nh.NetworkUnavailable
			if healthy {
				data.HealthyNodes++
			} else {
				data.UnhealthyNodes++
			}

			data.Nodes = append(data.Nodes, nh)
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
