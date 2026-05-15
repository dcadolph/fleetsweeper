package rbacaudit

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "rbac-audit"

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
	// WildcardRules is the number of RBAC rules using "*" for resources or verbs.
	WildcardRules int `json:"wildcard_rules"`
	// ClusterAdminBindings is the number of bindings to the cluster-admin role by non-system accounts.
	ClusterAdminBindings int `json:"cluster_admin_bindings"`
	// DefaultSABindings is the number of bindings that grant permissions to the "default" service account.
	DefaultSABindings int `json:"default_sa_bindings"`
	// AutomountTokenPods is the number of pods with automounted service account tokens.
	AutomountTokenPods int `json:"automount_token_pods"`
	// RiskBindings lists the most concerning bindings.
	RiskBindings []RiskBinding `json:"risk_bindings"`
}

// NewScanner returns a scanner that audits RBAC for over-permissive configurations.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		rbacClient := client.Clientset().RbacV1()
		data := Data{}

		// Check ClusterRoles for wildcard rules.
		crList, err := rbacClient.ClusterRoles().List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster roles: %w", scanner.ErrScan, Name, err)
		}
		wildcardRoles := make(map[string]bool)
		for _, cr := range crList.Items {
			for _, rule := range cr.Rules {
				hasWildcard := false
				for _, v := range rule.Verbs {
					if v == "*" {
						hasWildcard = true
						break
					}
				}
				if !hasWildcard {
					for _, r := range rule.Resources {
						if r == "*" {
							hasWildcard = true
							break
						}
					}
				}
				if hasWildcard {
					data.WildcardRules++
					wildcardRoles[cr.Name] = true
				}
			}
		}

		// Check ClusterRoleBindings for concerning patterns.
		crbList, err := rbacClient.ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster role bindings: %w", scanner.ErrScan, Name, err)
		}

		systemPrefixes := []string{"system:", "kubeadm:", "kube-"}
		for _, crb := range crbList.Items {
			var risks []string
			var subjectNames []string

			isSystem := false
			for _, prefix := range systemPrefixes {
				if len(crb.Name) >= len(prefix) && crb.Name[:len(prefix)] == prefix {
					isSystem = true
					break
				}
			}

			for _, s := range crb.Subjects {
				subjectNames = append(subjectNames, fmt.Sprintf("%s:%s/%s", s.Kind, s.Namespace, s.Name))

				if crb.RoleRef.Name == "cluster-admin" && !isSystem {
					data.ClusterAdminBindings++
					risks = append(risks, "cluster-admin-to-non-system")
				}
				if s.Kind == "ServiceAccount" && s.Name == "default" {
					data.DefaultSABindings++
					risks = append(risks, "grants-to-default-sa")
				}
			}

			if wildcardRoles[crb.RoleRef.Name] && !isSystem {
				risks = append(risks, "wildcard-role")
			}

			if len(risks) > 0 {
				data.RiskBindings = append(data.RiskBindings, RiskBinding{
					Kind:      "ClusterRoleBinding",
					Name:      crb.Name,
					RoleRef:   crb.RoleRef.Name,
					Subjects:  subjectNames,
					Risks:     risks,
				})
			}
		}

		// Check pods for automounted service account tokens.
		podList, err := client.Clientset().CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err == nil {
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

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}
