package service

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "services"

// ServiceInfo describes a single service.
type ServiceInfo struct {
	// Namespace is the namespace containing the service.
	Namespace string `json:"namespace"`
	// Name is the service name.
	Name string `json:"name"`
	// Type is the service type (ClusterIP, NodePort, LoadBalancer, ExternalName).
	Type string `json:"type"`
	// Ports lists the port specifications.
	Ports []PortInfo `json:"ports,omitempty"`
}

// PortInfo describes a single port on a service.
type PortInfo struct {
	// Name is the port name.
	Name string `json:"name,omitempty"`
	// Port is the service port number.
	Port int32 `json:"port"`
	// Protocol is the port protocol (TCP, UDP, SCTP).
	Protocol string `json:"protocol"`
}

// Data holds service information for one cluster.
type Data struct {
	// Count is the total number of services.
	Count int `json:"count"`
	// Services lists all services across all namespaces.
	Services []ServiceInfo `json:"services"`
}

// NewScanner returns a scanner that lists all services in a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		svcList, err := client.Clientset().CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		services := make([]ServiceInfo, 0, len(svcList.Items))
		for _, svc := range svcList.Items {
			info := ServiceInfo{
				Namespace: svc.Namespace,
				Name:      svc.Name,
				Type:      string(svc.Spec.Type),
			}
			for _, p := range svc.Spec.Ports {
				info.Ports = append(info.Ports, PortInfo{
					Name:     p.Name,
					Port:     p.Port,
					Protocol: string(p.Protocol),
				})
			}
			services = append(services, info)
		}
		sort.Slice(services, func(i, j int) bool {
			if services[i].Namespace != services[j].Namespace {
				return services[i].Namespace < services[j].Namespace
			}
			return services[i].Name < services[j].Name
		})

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Count:    len(services),
				Services: services,
			},
		}, nil
	})
}
