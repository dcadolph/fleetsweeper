package security

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
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
