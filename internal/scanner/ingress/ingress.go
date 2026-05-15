package ingress

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "ingresses"

// IngressInfo describes a single ingress resource.
type IngressInfo struct {
	// Namespace is the namespace containing the ingress.
	Namespace string `json:"namespace"`
	// Name is the ingress name.
	Name string `json:"name"`
	// IngressClassName is the ingress class (nil if unset).
	IngressClassName string `json:"ingress_class_name,omitempty"`
	// Hosts lists the hostnames configured on this ingress.
	Hosts []string `json:"hosts,omitempty"`
	// TLS indicates whether TLS is configured.
	TLS bool `json:"tls"`
}

// Data holds ingress information for one cluster.
type Data struct {
	// Count is the total number of ingress resources.
	Count int `json:"count"`
	// Ingresses lists all ingress resources.
	Ingresses []IngressInfo `json:"ingresses"`
}

// NewScanner returns a scanner that lists all ingress resources in a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		ingList, err := client.Clientset().NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		ingresses := make([]IngressInfo, 0, len(ingList.Items))
		for _, ing := range ingList.Items {
			info := IngressInfo{
				Namespace: ing.Namespace,
				Name:      ing.Name,
				TLS:       len(ing.Spec.TLS) > 0,
			}
			if ing.Spec.IngressClassName != nil {
				info.IngressClassName = *ing.Spec.IngressClassName
			}
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					info.Hosts = append(info.Hosts, rule.Host)
				}
			}
			ingresses = append(ingresses, info)
		}
		sort.Slice(ingresses, func(i, j int) bool {
			if ingresses[i].Namespace != ingresses[j].Namespace {
				return ingresses[i].Namespace < ingresses[j].Namespace
			}
			return ingresses[i].Name < ingresses[j].Name
		})

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Count:     len(ingresses),
				Ingresses: ingresses,
			},
		}, nil
	})
}
