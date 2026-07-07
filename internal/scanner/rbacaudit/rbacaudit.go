package rbacaudit

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "rbac-audit"

// systemPrefixes are name prefixes used as a last-resort heuristic when we
// cannot look up the referenced role's bootstrapping label. They catch the
// most common control-plane bindings that a user would never name themselves.
var systemPrefixes = []string{"system:", "kubeadm:", "kube-"}

// systemRoleLabel marks roles that ship with Kubernetes and should be treated
// as expected/system, even if a user authors a binding against one.
const systemRoleLabel = "kubernetes.io/bootstrapping"

// RiskBinding describes a ClusterRoleBinding or RoleBinding with concerning permissions.
type RiskBinding struct {
	// Kind is ClusterRoleBinding or RoleBinding.
	Kind string `json:"kind"`
	// Name is the binding name.
	Name string `json:"name"`
	// Namespace is empty for cluster-scoped bindings.
	Namespace string `json:"namespace,omitempty"`
	// RoleRef is the role being bound.
	RoleRef string `json:"role_ref"`
	// Subjects describes who gets the permissions.
	Subjects []string `json:"subjects"`
	// Risks lists the specific concerns.
	Risks []string `json:"risks"`
}

// Data holds RBAC audit results for one cluster.
type Data struct {
	// WildcardRules is the number of RBAC rules using "*" for resources, verbs, or apiGroups.
	WildcardRules int `json:"wildcard_rules"`
	// ClusterAdminBindings is the number of bindings to the cluster-admin role by non-system principals.
	ClusterAdminBindings int `json:"cluster_admin_bindings"`
	// DefaultSABindings is the number of bindings that grant permissions to a "default" service account.
	DefaultSABindings int `json:"default_sa_bindings"`
	// AutomountTokenPods is the number of pods with automounted service account tokens.
	AutomountTokenPods int `json:"automount_token_pods"`
	// RoleBindingsAudited is the number of namespaced RoleBindings audited.
	RoleBindingsAudited int `json:"role_bindings_audited"`
	// RiskBindings lists the most concerning bindings.
	RiskBindings []RiskBinding `json:"risk_bindings"`
}

// NewScanner returns a scanner that audits RBAC for over-permissive configurations.
// Counters increment per binding (not per subject) so a single binding with N
// subjects no longer inflates the total by a factor of N.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		rbacClient := client.Clientset().RbacV1()
		data := Data{}

		crList, err := rbacClient.ClusterRoles().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster roles: %w", scanner.ErrScan, Name, err)
		}

		systemRoles := make(map[string]bool)
		wildcardRoles := make(map[string]bool)
		for i := range crList.Items {
			cr := &crList.Items[i]
			if _, ok := cr.Labels[systemRoleLabel]; ok {
				systemRoles[cr.Name] = true
			}
			for _, rule := range cr.Rules {
				if ruleHasWildcard(rule.Verbs) || ruleHasWildcard(rule.Resources) || ruleHasWildcard(rule.APIGroups) {
					data.WildcardRules++
					wildcardRoles[cr.Name] = true
				}
			}
		}

		crbList, err := rbacClient.ClusterRoleBindings().List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster role bindings: %w", scanner.ErrScan, Name, err)
		}

		for i := range crbList.Items {
			crb := &crbList.Items[i]
			isSystem := isSystemBinding(crb.Name, crb.RoleRef.Name, systemRoles)

			subjectNames := make([]string, 0, len(crb.Subjects))
			grantsToDefaultSA := false
			for _, s := range crb.Subjects {
				subjectNames = append(subjectNames, fmt.Sprintf("%s:%s/%s", s.Kind, s.Namespace, s.Name))
				if s.Kind == "ServiceAccount" && s.Name == "default" {
					grantsToDefaultSA = true
				}
			}

			var risks []string
			if crb.RoleRef.Name == "cluster-admin" && !isSystem {
				data.ClusterAdminBindings++
				risks = append(risks, "cluster-admin-to-non-system")
			}
			if grantsToDefaultSA {
				data.DefaultSABindings++
				risks = append(risks, "grants-to-default-sa")
			}
			if wildcardRoles[crb.RoleRef.Name] && !isSystem {
				risks = append(risks, "wildcard-role")
			}

			if len(risks) > 0 {
				data.RiskBindings = append(data.RiskBindings, RiskBinding{
					Kind:     "ClusterRoleBinding",
					Name:     crb.Name,
					RoleRef:  crb.RoleRef.Name,
					Subjects: subjectNames,
					Risks:    risks,
				})
			}
		}

		var degraded []string

		rbList, rbErr := rbacClient.RoleBindings("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if rbErr != nil {
			degraded = append(degraded, fmt.Sprintf("role bindings: %v", rbErr))
		} else {
			data.RoleBindingsAudited = len(rbList.Items)
			for i := range rbList.Items {
				rb := &rbList.Items[i]
				isSystem := isSystemBinding(rb.Name, rb.RoleRef.Name, systemRoles)

				subjectNames := make([]string, 0, len(rb.Subjects))
				grantsToDefaultSA := false
				for _, s := range rb.Subjects {
					subjectNames = append(subjectNames, fmt.Sprintf("%s:%s/%s", s.Kind, s.Namespace, s.Name))
					if s.Kind == "ServiceAccount" && s.Name == "default" {
						grantsToDefaultSA = true
					}
				}

				var risks []string
				if rb.RoleRef.Name == "cluster-admin" && !isSystem {
					data.ClusterAdminBindings++
					risks = append(risks, "cluster-admin-to-non-system")
				}
				if grantsToDefaultSA {
					data.DefaultSABindings++
					risks = append(risks, "grants-to-default-sa")
				}
				if wildcardRoles[rb.RoleRef.Name] && !isSystem {
					risks = append(risks, "wildcard-role")
				}

				if len(risks) > 0 {
					data.RiskBindings = append(data.RiskBindings, RiskBinding{
						Kind:      "RoleBinding",
						Name:      rb.Name,
						Namespace: rb.Namespace,
						RoleRef:   rb.RoleRef.Name,
						Subjects:  subjectNames,
						Risks:     risks,
					})
				}
			}
		}

		podList, podErr := client.Clientset().CoreV1().Pods("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if podErr != nil {
			degraded = append(degraded, fmt.Sprintf("pods: %v", podErr))
		} else {
			for _, pod := range podList.Items {
				automount := true
				if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
					automount = false
				}
				if automount {
					data.AutomountTokenPods++
				}
			}
		}

		sort.Slice(data.RiskBindings, func(i, j int) bool {
			return len(data.RiskBindings[i].Risks) > len(data.RiskBindings[j].Risks)
		})
		if len(data.RiskBindings) > 30 {
			data.RiskBindings = data.RiskBindings[:30]
		}

		result := scanner.Result{Scanner: Name, Data: data}
		if len(degraded) > 0 {
			result.State = scanner.StateDegraded
			result.Reason = "partial data: " + strings.Join(degraded, "; ")
		}
		return result, nil
	})
}

// isSystemBinding reports whether a binding should be treated as a system
// binding for the purposes of audit. It first checks the role's
// rbac-bootstrapping label (the authoritative signal), then falls back to a
// name-prefix heuristic so we still recognize system bindings when we cannot
// resolve the role itself.
func isSystemBinding(bindingName, roleName string, systemRoles map[string]bool) bool {
	if systemRoles[roleName] {
		return true
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(bindingName, prefix) {
			return true
		}
	}
	return false
}

// ruleHasWildcard reports whether any element of the slice equals "*".
func ruleHasWildcard(items []string) bool {
	return slices.Contains(items, "*")
}
