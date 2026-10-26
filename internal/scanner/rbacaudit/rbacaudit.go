package rbacaudit

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

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
		var cov scanner.Coverage

		crList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.ClusterRoles().List,
			func(l *rbacv1.ClusterRoleList) []rbacv1.ClusterRole { return l.Items })
		if !cov.Require("cluster roles", err) {
			crList = nil
		}

		systemRoles := make(map[string]bool)
		wildcardRoles := make(map[string]bool)
		for i := range crList {
			cr := &crList[i]
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

		crbList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.ClusterRoleBindings().List,
			func(l *rbacv1.ClusterRoleBindingList) []rbacv1.ClusterRoleBinding { return l.Items })
		if !cov.Require("cluster role bindings", err) {
			crbList = nil
		}

		for i := range crbList {
			crb := &crbList[i]
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

		rbList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.RoleBindings("").List,
			func(l *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return l.Items })
		if cov.Observe("role bindings", err) {
			data.RoleBindingsAudited = len(rbList)
			for i := range rbList {
				rb := &rbList[i]
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

		podList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), client.Clientset().CoreV1().Pods("").List,
			func(l *corev1.PodList) []corev1.Pod { return l.Items })
		if cov.Observe("pods", err) {
			for _, pod := range podList {
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

		return cov.Finish(Name, data)
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
