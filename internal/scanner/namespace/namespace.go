package namespace

import (
	"context"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "namespaces"

// Data holds namespace information for one cluster.
type Data struct {
	// Count is the total number of namespaces.
	Count int `json:"count"`
	// Names lists all namespace names in sorted order.
	Names []string `json:"names"`
	// Labels maps namespace name to its label set.
	Labels map[string]map[string]string `json:"labels,omitempty"`
}

// NewScanner returns a scanner that lists all namespaces in a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		var cov scanner.Coverage
		nsList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(),
			client.Clientset().CoreV1().Namespaces().List,
			func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })

		names := make([]string, 0, len(nsList))
		labels := make(map[string]map[string]string, len(nsList))
		if cov.Observe("namespaces", err) {
			for _, ns := range nsList {
				names = append(names, ns.Name)
				if len(ns.Labels) > 0 {
					labels[ns.Name] = ns.Labels
				}
			}
		}
		sort.Strings(names)

		return cov.Finish(Name, Data{
			Count:  len(names),
			Names:  names,
			Labels: labels,
		})
	})
}
