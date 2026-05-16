package networkpolicy

import (
	"context"
	"fmt"
	"sort"


	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "network-policies"

// PolicyInfo describes a single NetworkPolicy.
type PolicyInfo struct {
	// Namespace is the namespace containing the policy.
	Namespace string `json:"namespace"`
	// Name is the policy name.
	Name string `json:"name"`
	// PolicyTypes lists the policy types (Ingress, Egress).
	PolicyTypes []string `json:"policy_types"`
	// IngressRuleCount is the number of ingress rules.
	IngressRuleCount int `json:"ingress_rule_count"`
	// EgressRuleCount is the number of egress rules.
	EgressRuleCount int `json:"egress_rule_count"`
}

// Data holds network policy information for one cluster.
type Data struct {
	// Count is the total number of network policies.
	Count int `json:"count"`
	// NamespacesWithPolicies is the number of namespaces that have at least one policy.
	NamespacesWithPolicies int `json:"namespaces_with_policies"`
	// NamespacesWithoutPolicies is the number of namespaces lacking any policy.
	NamespacesWithoutPolicies int `json:"namespaces_without_policies"`
	// Policies lists all network policies.
	Policies []PolicyInfo `json:"policies"`
}

// NewScanner returns a scanner that collects NetworkPolicy data from a cluster.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		npList, err := client.Clientset().NetworkingV1().NetworkPolicies("").List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		nsList, err := client.Clientset().CoreV1().Namespaces().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: namespaces: %w", scanner.ErrScan, Name, err)
		}

		namespacesWithPolicy := make(map[string]struct{})
		policies := make([]PolicyInfo, 0, len(npList.Items))
		for _, np := range npList.Items {
			namespacesWithPolicy[np.Namespace] = struct{}{}
			policyTypes := make([]string, 0, len(np.Spec.PolicyTypes))
			for _, pt := range np.Spec.PolicyTypes {
				policyTypes = append(policyTypes, string(pt))
			}
			policies = append(policies, PolicyInfo{
				Namespace:        np.Namespace,
				Name:             np.Name,
				PolicyTypes:      policyTypes,
				IngressRuleCount: len(np.Spec.Ingress),
				EgressRuleCount:  len(np.Spec.Egress),
			})
		}
		sort.Slice(policies, func(i, j int) bool {
			if policies[i].Namespace != policies[j].Namespace {
				return policies[i].Namespace < policies[j].Namespace
			}
			return policies[i].Name < policies[j].Name
		})

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Count:                     len(policies),
				NamespacesWithPolicies:    len(namespacesWithPolicy),
				NamespacesWithoutPolicies: len(nsList.Items) - len(namespacesWithPolicy),
				Policies:                  policies,
			},
		}, nil
	})
}
