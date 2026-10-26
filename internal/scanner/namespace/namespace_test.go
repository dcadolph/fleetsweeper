package namespace

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

	tests := []struct {
		WantCount  int
		WantNames  []string
		Namespaces []*corev1.Namespace
	}{{ // Test 0: Multiple namespaces returned sorted.
		Namespaces: []*corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
		},
		WantCount: 3,
		WantNames: []string{"apps", "default", "kube-system"},
	}, { // Test 1: Empty cluster.
		Namespaces: []*corev1.Namespace{},
		WantCount:  0,
		WantNames:  []string{},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			objects := make([]runtime.Object, len(test.Namespaces))
			for i, ns := range test.Namespaces {
				objects[i] = ns
			}
			cs := fakeclientset.NewSimpleClientset(objects...)
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			if diff := cmp.Diff(test.WantCount, data.Count); diff != "" {
				t.Errorf("count mismatch (-want +got):\n%s", diff)
			}
			if data.Names == nil {
				data.Names = []string{}
			}
			if diff := cmp.Diff(test.WantNames, data.Names); diff != "" {
				t.Errorf("names mismatch (-want +got):\n%s", diff)
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
