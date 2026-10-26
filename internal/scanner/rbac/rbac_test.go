package rbac

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	}{{ // Test 0: Cluster roles denied.
		Resource: "clusterroles",
	}, { // Test 1: Roles denied.
		Resource: "roles",
	}, { // Test 2: Cluster role bindings denied.
		Resource: "clusterrolebindings",
	}, { // Test 3: Role bindings denied.
		Resource: "rolebindings",
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
