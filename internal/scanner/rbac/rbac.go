package rbac

import (
	"context"
	"fmt"
	"sort"


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

		crList, err := rbacClient.ClusterRoles().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster roles: %w", scanner.ErrScan, Name, err)
		}
		data.ClusterRoleCount = len(crList.Items)
		for _, cr := range crList.Items {
			data.Roles = append(data.Roles, RoleInfo{
				Kind:      "ClusterRole",
				Name:      cr.Name,
				RuleCount: len(cr.Rules),
			})
		}

		rList, err := rbacClient.Roles("").List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: roles: %w", scanner.ErrScan, Name, err)
		}
		data.RoleCount = len(rList.Items)
		for _, r := range rList.Items {
			data.Roles = append(data.Roles, RoleInfo{
				Kind:      "Role",
				Namespace: r.Namespace,
				Name:      r.Name,
				RuleCount: len(r.Rules),
			})
		}

		crbList, err := rbacClient.ClusterRoleBindings().List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: cluster role bindings: %w", scanner.ErrScan, Name, err)
		}
		data.ClusterRoleBindingCount = len(crbList.Items)
		for _, crb := range crbList.Items {
			data.Bindings = append(data.Bindings, BindingInfo{
				Kind:         "ClusterRoleBinding",
				Name:         crb.Name,
				RoleRef:      crb.RoleRef.Name,
				SubjectCount: len(crb.Subjects),
			})
		}

		rbList, err := rbacClient.RoleBindings("").List(ctx, scanner.CacheReadOptions())
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: role bindings: %w", scanner.ErrScan, Name, err)
		}
		data.RoleBindingCount = len(rbList.Items)
		for _, rb := range rbList.Items {
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

		return scanner.Result{
			Scanner: Name,
			Data:    data,
		}, nil
	})
}
