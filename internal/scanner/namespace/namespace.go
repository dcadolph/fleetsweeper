package namespace

import (
	"context"
	"fmt"
	"sort"


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
		nsList, err := client.Clientset().CoreV1().Namespaces().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		names := make([]string, 0, len(nsList.Items))
		labels := make(map[string]map[string]string, len(nsList.Items))
		for _, ns := range nsList.Items {
			names = append(names, ns.Name)
			if len(ns.Labels) > 0 {
				labels[ns.Name] = ns.Labels
			}
		}
		sort.Strings(names)

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Count:  len(names),
				Names:  names,
				Labels: labels,
			},
		}, nil
	})
}
