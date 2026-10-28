// Package networkpolicy implements the scanner that collects NetworkPolicy data from a cluster.
package networkpolicy

import (
	"context"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

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
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		var cov scanner.Coverage
		cs := client.Clientset()
		npList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), cs.NetworkingV1().NetworkPolicies("").List,
			func(l *networkingv1.NetworkPolicyList) []networkingv1.NetworkPolicy { return l.Items })
		if !cov.Require("network policies", err) {
			npList = nil
		}

		nsList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), cs.CoreV1().Namespaces().List,
			func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })
		if !cov.Require("namespaces", err) {
			nsList = nil
		}

		namespacesWithPolicy := make(map[string]struct{})
		policies := make([]PolicyInfo, 0, len(npList))
		for _, np := range npList {
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

		return cov.Finish(Name, Data{
			Count:                     len(policies),
			NamespacesWithPolicies:    len(namespacesWithPolicy),
			NamespacesWithoutPolicies: len(nsList) - len(namespacesWithPolicy),
			Policies:                  policies,
		})
	})
}
