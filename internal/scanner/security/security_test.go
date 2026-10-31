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

// testNamespace returns a namespace named name whose PSS enforce label is enforce, or unlabeled
// when enforce is empty.
func testNamespace(name, enforce string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if enforce != "" {
		ns.Labels = map[string]string{"pod-security.kubernetes.io/enforce": enforce}
	}
	return ns
}

// TestNewScanner checks the enforced and unenforced counts and the level distribution.
func TestNewScanner(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantLevels     map[string]int
		Namespaces     []runtime.Object
		WantCount      int
		WantEnforced   int
		WantUnenforced int
	}{{ // Test 0: One restricted and one unlabeled namespace.
		Namespaces:     []runtime.Object{testNamespace("prod", "restricted"), testNamespace("dev", "")},
		WantCount:      2,
		WantEnforced:   1,
		WantUnenforced: 1,
		WantLevels:     map[string]int{"restricted": 1, "none": 1},
	}, { // Test 1: Enforce privileged enforces nothing, so it counts as unenforced.
		Namespaces: []runtime.Object{
			testNamespace("prod", "baseline"),
			testNamespace("kube-system", "privileged"),
		},
		WantCount:      2,
		WantEnforced:   1,
		WantUnenforced: 1,
		WantLevels:     map[string]int{"baseline": 1, "privileged": 1},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fakeclientset.NewSimpleClientset(test.Namespaces...)
			client := kube.NewTestClientWithClientset("test", cs)
			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			got := []int{data.NamespaceCount, data.EnforcedCount, data.UnenforcedCount}
			want := []int{test.WantCount, test.WantEnforced, test.WantUnenforced}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("namespace, enforced, unenforced counts mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantLevels, data.LevelDistribution); diff != "" {
				t.Errorf("level distribution mismatch (-want +got):\n%s", diff)
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
