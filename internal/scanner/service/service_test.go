package service

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
		WantCount    int
		WantFirstSvc string
		Services     []corev1.Service
	}{{ // Test 0: Multiple services sorted by namespace then name.
		Services: []corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP}},
				},
			},
		},
		WantCount:    2,
		WantFirstSvc: "api",
	}, { // Test 1: No services.
		Services:     []corev1.Service{},
		WantCount:    0,
		WantFirstSvc: "",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			objects := make([]runtime.Object, len(test.Services))
			for i := range test.Services {
				objects[i] = &test.Services[i]
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
			if test.WantFirstSvc != "" && len(data.Services) > 0 {
				if diff := cmp.Diff(test.WantFirstSvc, data.Services[0].Name); diff != "" {
					t.Errorf("first service mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
