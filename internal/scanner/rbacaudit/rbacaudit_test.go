package rbacaudit

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// wildcardRole builds a ClusterRole whose single rule uses "*" for verbs.
func wildcardRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"pods"}, APIGroups: []string{""}}},
	}
}

// crb builds a ClusterRoleBinding to roleRef with the given subjects.
func crb(name, roleRef string, subjects ...rbacv1.Subject) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Name: roleRef},
		Subjects:   subjects,
	}
}

// pod builds a Pod whose automount preference is set by mount.
func pod(name string, mount *bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       corev1.PodSpec{AutomountServiceAccountToken: mount},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	falseVal := false
	userAlice := rbacv1.Subject{Kind: "User", Name: "alice"}
	defaultSA := rbacv1.Subject{Kind: "ServiceAccount", Namespace: "default", Name: "default"}

	tests := []struct {
		Name                     string
		Objects                  []runtime.Object
		WantWildcardRules        int
		WantClusterAdminBindings int
		WantDefaultSABindings    int
		WantAutomountTokenPods   int
		WantRiskBindings         int
	}{{ // Test 0: Empty cluster, everything zero.
		Name: "empty",
	}, { // Test 1: Non-system cluster-admin binding is flagged.
		Name: "cluster-admin to user",
		Objects: []runtime.Object{
			crb("grant-admin", "cluster-admin", userAlice),
		},
		WantClusterAdminBindings: 1,
		WantRiskBindings:         1,
	}, { // Test 2: system: prefixed binding to cluster-admin is not flagged.
		Name: "system binding excluded",
		Objects: []runtime.Object{
			crb("system:controller", "cluster-admin", userAlice),
		},
		WantClusterAdminBindings: 0,
		WantRiskBindings:         0,
	}, { // Test 3: Wildcard role plus a binding to it and a default SA grant.
		Name: "wildcard and default sa",
		Objects: []runtime.Object{
			wildcardRole("god-mode"),
			crb("bind-god", "god-mode", defaultSA),
		},
		WantWildcardRules:     1,
		WantDefaultSABindings: 1,
		WantRiskBindings:      1,
	}, { // Test 4: Pods count toward automount unless explicitly disabled.
		Name: "automount accounting",
		Objects: []runtime.Object{
			pod("mounted", nil),
			pod("also-mounted", nil),
			pod("opted-out", &falseVal),
		},
		WantAutomountTokenPods: 2,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset(test.Objects...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}

			if diff := cmp.Diff(test.WantWildcardRules, data.WildcardRules); diff != "" {
				t.Errorf("wildcard rules mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantClusterAdminBindings, data.ClusterAdminBindings); diff != "" {
				t.Errorf("cluster-admin bindings mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantDefaultSABindings, data.DefaultSABindings); diff != "" {
				t.Errorf("default SA bindings mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantAutomountTokenPods, data.AutomountTokenPods); diff != "" {
				t.Errorf("automount pods mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantRiskBindings, len(data.RiskBindings)); diff != "" {
				t.Errorf("risk bindings count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
