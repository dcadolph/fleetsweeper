package security

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
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

	enforced := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prod",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "restricted",
			},
		},
	}
	unenforced := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "dev"},
	}

	cs := fakeclientset.NewSimpleClientset(enforced, unenforced)
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := result.Data.(Data)
	if !ok {
		t.Fatalf("expected Data type, got %T", result.Data)
	}

	if diff := cmp.Diff(2, data.NamespaceCount); diff != "" {
		t.Errorf("namespace count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.EnforcedCount); diff != "" {
		t.Errorf("enforced count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.UnenforcedCount); diff != "" {
		t.Errorf("unenforced count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, data.LevelDistribution["restricted"]); diff != "" {
		t.Errorf("restricted count mismatch (-want +got):\n%s", diff)
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
