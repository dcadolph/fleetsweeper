package rbac

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

func TestNewScanner(t *testing.T) {
	t.Parallel()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "admin"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
		RoleRef:    rbacv1.RoleRef{Name: "admin"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "apps"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"deployments"}}},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "deployer-binding", Namespace: "apps"},
		RoleRef:    rbacv1.RoleRef{Name: "deployer"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deploy-sa"}},
	}

	cs := fakeclientset.NewSimpleClientset(cr, crb, role, rb)
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}

	if diff := cmp.Diff(1, data.ClusterRoleCount); diff != "" {
		t.Errorf("cluster role count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.RoleCount); diff != "" {
		t.Errorf("role count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.ClusterRoleBindingCount); diff != "" {
		t.Errorf("cluster role binding count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.RoleBindingCount); diff != "" {
		t.Errorf("role binding count mismatch (-want +got):\n%s", diff)
	}
}
