package rbacaudit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
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

// failingClientset returns a fake clientset seeded with objs that errors when
// listing any of the named resources, used to exercise the degraded path.
func failingClientset(objs []runtime.Object, failResources ...string) *fakeclientset.Clientset {
	cs := fakeclientset.NewSimpleClientset(objs...)
	for _, res := range failResources {
		cs.PrependReactor("list", res, func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("list failed")
		})
	}
	return cs
}

// TestNewScannerDegraded verifies a failed RoleBinding or Pod list keeps the
// ClusterRoleBinding findings but marks the result degraded and names which
// listing failed, rather than silently dropping the failure.
func TestNewScannerDegraded(t *testing.T) {
	t.Parallel()

	userAlice := rbacv1.Subject{Kind: "User", Name: "alice"}

	tests := []struct {
		Name          string
		FailResources []string
		WantReasonHas []string
	}{{ // Test 0: RoleBinding list failure degrades, keeps cluster-admin count.
		Name:          "role bindings fail",
		FailResources: []string{"rolebindings"},
		WantReasonHas: []string{"role bindings"},
	}, { // Test 1: Pod list failure degrades.
		Name:          "pods fail",
		FailResources: []string{"pods"},
		WantReasonHas: []string{"pods"},
	}, { // Test 2: Both failing name both listings in the reason.
		Name:          "both fail",
		FailResources: []string{"rolebindings", "pods"},
		WantReasonHas: []string{"role bindings", "pods"},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			objs := []runtime.Object{crb("grant-admin", "cluster-admin", userAlice)}
			cs := failingClientset(objs, test.FailResources...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(scanner.StateDegraded, result.State); diff != "" {
				t.Errorf("state mismatch (-want +got):\n%s", diff)
			}
			for _, want := range test.WantReasonHas {
				if !strings.Contains(result.Reason, want) {
					t.Errorf("reason %q should mention %q", result.Reason, want)
				}
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			if diff := cmp.Diff(1, data.ClusterAdminBindings); diff != "" {
				t.Errorf("partial data lost, cluster-admin bindings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
