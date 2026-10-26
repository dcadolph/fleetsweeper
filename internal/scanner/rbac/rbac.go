// Package rbac scans the cluster's RBAC graph (ClusterRoles, RoleBindings, ServiceAccounts) and flags wildcard permissions and over-broad bindings.
package rbac

import (
	"context"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "rbac"

// RoleInfo describes a ClusterRole or Role.
type RoleInfo struct {
	// Kind is "ClusterRole" or "Role".
	Kind string `json:"kind"`
	// Namespace is empty for ClusterRoles.
	Namespace string `json:"namespace,omitempty"`
	// Name is the role name.
	Name string `json:"name"`
	// RuleCount is the number of policy rules attached.
	RuleCount int `json:"rule_count"`
}

// BindingInfo describes a ClusterRoleBinding or RoleBinding.
type BindingInfo struct {
	// Kind is "ClusterRoleBinding" or "RoleBinding".
	Kind string `json:"kind"`
	// Namespace is empty for ClusterRoleBindings.
	Namespace string `json:"namespace,omitempty"`
	// Name is the binding name.
	Name string `json:"name"`
	// RoleRef is the name of the role being bound.
	RoleRef string `json:"role_ref"`
	// SubjectCount is the number of subjects in the binding.
	SubjectCount int `json:"subject_count"`
}

// Data holds RBAC information for one cluster.
type Data struct {
	// ClusterRoleCount is the number of ClusterRoles.
	ClusterRoleCount int `json:"cluster_role_count"`
	// RoleCount is the number of namespaced Roles.
	RoleCount int `json:"role_count"`
	// ClusterRoleBindingCount is the number of ClusterRoleBindings.
	ClusterRoleBindingCount int `json:"cluster_role_binding_count"`
	// RoleBindingCount is the number of namespaced RoleBindings.
	RoleBindingCount int `json:"role_binding_count"`
	// Roles lists all ClusterRoles and Roles.
	Roles []RoleInfo `json:"roles"`
	// Bindings lists all ClusterRoleBindings and RoleBindings.
	Bindings []BindingInfo `json:"bindings"`
}

// NewScanner returns a scanner that collects RBAC configuration from a cluster.
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
		data.ClusterRoleCount = len(crList)
		for _, cr := range crList {
			data.Roles = append(data.Roles, RoleInfo{
				Kind:      "ClusterRole",
				Name:      cr.Name,
				RuleCount: len(cr.Rules),
			})
		}

		rList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.Roles("").List,
			func(l *rbacv1.RoleList) []rbacv1.Role { return l.Items })
		if !cov.Require("roles", err) {
			rList = nil
		}
		data.RoleCount = len(rList)
		for _, r := range rList {
			data.Roles = append(data.Roles, RoleInfo{
				Kind:      "Role",
				Namespace: r.Namespace,
				Name:      r.Name,
				RuleCount: len(r.Rules),
			})
		}

		crbList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.ClusterRoleBindings().List,
			func(l *rbacv1.ClusterRoleBindingList) []rbacv1.ClusterRoleBinding { return l.Items })
		if !cov.Require("cluster role bindings", err) {
			crbList = nil
		}
		data.ClusterRoleBindingCount = len(crbList)
		for _, crb := range crbList {
			data.Bindings = append(data.Bindings, BindingInfo{
				Kind:         "ClusterRoleBinding",
				Name:         crb.Name,
				RoleRef:      crb.RoleRef.Name,
				SubjectCount: len(crb.Subjects),
			})
		}

		rbList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), rbacClient.RoleBindings("").List,
			func(l *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return l.Items })
		if !cov.Require("role bindings", err) {
			rbList = nil
		}
		data.RoleBindingCount = len(rbList)
		for _, rb := range rbList {
			data.Bindings = append(data.Bindings, BindingInfo{
				Kind:         "RoleBinding",
				Namespace:    rb.Namespace,
				Name:         rb.Name,
				RoleRef:      rb.RoleRef.Name,
				SubjectCount: len(rb.Subjects),
			})
		}

		sort.Slice(data.Roles, func(i, j int) bool {
			if data.Roles[i].Kind != data.Roles[j].Kind {
				return data.Roles[i].Kind < data.Roles[j].Kind
			}
			return data.Roles[i].Name < data.Roles[j].Name
		})
		sort.Slice(data.Bindings, func(i, j int) bool {
			if data.Bindings[i].Kind != data.Bindings[j].Kind {
				return data.Bindings[i].Kind < data.Bindings[j].Kind
			}
			return data.Bindings[i].Name < data.Bindings[j].Name
		})

		return cov.Finish(Name, data)
	})
}
