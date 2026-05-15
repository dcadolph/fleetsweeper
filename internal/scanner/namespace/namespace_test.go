package namespace

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
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
