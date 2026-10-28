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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

// labeled returns obj with the bootstrapping label set, as Kubernetes sets it on built-in objects.
func labeled[T interface{ SetLabels(map[string]string) }](obj T) T {
	obj.SetLabels(map[string]string{systemBindingLabel: "rbac-defaults"})
	return obj
}

// rb builds a RoleBinding in namespace ns to roleRef with the given subjects.
func rb(ns, name, roleRef string, subjects ...rbacv1.Subject) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleRef},
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
	masters := rbacv1.Subject{Kind: "Group", Name: "system:masters"}
	unauthenticated := rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}
	anonymous := rbacv1.Subject{Kind: "User", Name: "system:anonymous"}
	clusterAdmin := labeled(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}}},
	})

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
	}, { // Test 5: A bootstrapping label on the role does not make a user binding system.
		Name: "labeled cluster-admin role",
		Objects: []runtime.Object{
			clusterAdmin,
			crb("grant-admin", "cluster-admin", userAlice),
		},
		WantWildcardRules:        1,
		WantClusterAdminBindings: 1,
		WantRiskBindings:         1,
	}, { // Test 6: The built-in cluster-admin binding carries its own label and is system.
		Name: "labeled binding excluded",
		Objects: []runtime.Object{
			clusterAdmin,
			labeled(crb("cluster-admin", "cluster-admin", masters)),
		},
		WantWildcardRules: 1,
	}, { // Test 7: kubeadm: prefixed binding to cluster-admin is not flagged.
		Name: "kubeadm binding excluded",
		Objects: []runtime.Object{
			clusterAdmin,
			crb("kubeadm:cluster-admins", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "kubeadm:cluster-admins"}),
		},
		WantWildcardRules: 1,
	}, { // Test 8: A system: prefix does not hide a grant to unauthenticated callers.
		Name: "system prefix to unauthenticated",
		Objects: []runtime.Object{
			clusterAdmin,
			crb("system:open", "cluster-admin", unauthenticated),
		},
		WantWildcardRules:        1,
		WantClusterAdminBindings: 1,
		WantRiskBindings:         1,
	}, { // Test 9: A bootstrapping label does not hide a grant to anonymous callers.
		Name: "labeled binding to anonymous",
		Objects: []runtime.Object{
			clusterAdmin,
			labeled(crb("open-door", "cluster-admin", anonymous)),
		},
		WantWildcardRules:        1,
		WantClusterAdminBindings: 1,
		WantRiskBindings:         1,
	}, { // Test 10: A namespaced user binding to the labeled cluster-admin role is flagged.
		Name: "role binding to cluster-admin",
		Objects: []runtime.Object{
			clusterAdmin,
			rb("team-a", "team-admin", "cluster-admin", userAlice),
		},
		WantWildcardRules:        1,
		WantClusterAdminBindings: 1,
		WantRiskBindings:         1,
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

// TestScanListErrors verifies a failed list is classified instead of read as an empty cluster.
func TestScanListErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Err       error
		Want      error
		WantState scanner.State
	}{{ // Test 0: Forbidden lists error the scan.
		Err:  apierrors.NewForbidden(schema.GroupResource{Resource: "x"}, "", errors.New("rbac denied")),
		Want: scanner.ErrScan, WantState: scanner.StateErrored,
	}, { // Test 1: A resource type the server does not serve is unavailable.
		Err:       apierrors.NewNotFound(schema.GroupResource{Resource: "x"}, ""),
		WantState: scanner.StateUnavailable,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fakeclientset.NewSimpleClientset()
			cs.PrependReactor("list", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, test.Err
			})
			result, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithClientset("test", cs))
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if result.State != test.WantState {
				t.Errorf("state = %q, want %q", result.State, test.WantState)
			}
		})
	}
}

// TestScanRequiredReadFails verifies that one failed required list errors the scan with no data,
// even when the other lists succeed, so the derived counts never read as a clean cluster.
func TestScanRequiredReadFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Resource string
	}{{ // Test 0: Cluster roles denied, so wildcard rules cannot be counted.
		Resource: "clusterroles",
	}, { // Test 1: Cluster role bindings denied.
		Resource: "clusterrolebindings",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fakeclientset.NewSimpleClientset()
			cs.PrependReactor("list", test.Resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: test.Resource}, "", errors.New("rbac denied"))
			})
			result, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithClientset("test", cs))
			if !errors.Is(err, scanner.ErrScan) {
				t.Fatalf("err = %v, want %v", err, scanner.ErrScan)
			}
			if result.State != scanner.StateErrored || result.Data != nil {
				t.Errorf("result = %q with data %v, want errored with no data", result.State, result.Data)
			}
		})
	}
}
