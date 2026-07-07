package quota

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// errBoom is a sentinel error injected into fake client reactors.
var errBoom = errors.New("boom")

// mustQuantity parses a resource quantity string and panics on failure.
func mustQuantity(s string) resource.Quantity {
	return resource.MustParse(s)
}

// resourceQuota builds a ResourceQuota with the given hard and used resource lists.
func resourceQuota(namespace, name string, hard, used corev1.ResourceList) *corev1.ResourceQuota {
	return &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ResourceQuotaSpec{Hard: hard},
		Status:     corev1.ResourceQuotaStatus{Used: used},
	}
}

// limitRange builds a LimitRange with the given number of limit items.
func limitRange(namespace, name string, items int) *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.LimitRangeSpec{Limits: make([]corev1.LimitRangeItem, items)},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name                     string
		WantFirstQuotaNS         string
		WantFirstQuotaName       string
		WantFirstHard            map[string]string
		WantFirstUsed            map[string]string
		WantLRKeys               []string
		Objects                  []runtime.Object
		WantQuotaCount           int
		WantLimitRangeCount      int
		WantNamespacesWithQuotas int
		WantFirstLRItemCount     int
	}{{ // Test 0: Empty cluster reports zero quotas and limit ranges.
		Name:                     "empty",
		Objects:                  nil,
		WantQuotaCount:           0,
		WantLimitRangeCount:      0,
		WantNamespacesWithQuotas: 0,
	}, { // Test 1: Two quotas in distinct namespaces plus one limit range.
		Name: "two namespaces with limit range",
		Objects: []runtime.Object{
			resourceQuota("apps", "compute",
				corev1.ResourceList{
					corev1.ResourceCPU:    mustQuantity("2"),
					corev1.ResourceMemory: mustQuantity("1Gi"),
				},
				corev1.ResourceList{corev1.ResourceCPU: mustQuantity("500m")}),
			resourceQuota("web", "compute",
				corev1.ResourceList{corev1.ResourcePods: mustQuantity("10")}, nil),
			limitRange("apps", "limits", 2),
		},
		WantQuotaCount:           2,
		WantLimitRangeCount:      1,
		WantNamespacesWithQuotas: 2,
		WantFirstQuotaNS:         "apps",
		WantFirstQuotaName:       "compute",
		WantFirstHard:            map[string]string{"cpu": "2", "memory": "1Gi"},
		WantFirstUsed:            map[string]string{"cpu": "500m"},
		WantFirstLRItemCount:     2,
	}, { // Test 2: Two quotas in the same namespace count coverage once.
		Name: "two quotas one namespace",
		Objects: []runtime.Object{
			resourceQuota("apps", "z-quota",
				corev1.ResourceList{corev1.ResourcePods: mustQuantity("5")}, nil),
			resourceQuota("apps", "a-quota",
				corev1.ResourceList{corev1.ResourcePods: mustQuantity("5")}, nil),
		},
		WantQuotaCount:           2,
		WantLimitRangeCount:      0,
		WantNamespacesWithQuotas: 1,
		WantFirstQuotaNS:         "apps",
		WantFirstQuotaName:       "a-quota",
		WantFirstHard:            map[string]string{"pods": "5"},
	}, { // Test 3: Limit ranges sort by namespace then name.
		Name: "limit range sorting",
		Objects: []runtime.Object{
			limitRange("web", "z-limits", 1),
			limitRange("apps", "b-limits", 2),
			limitRange("apps", "a-limits", 3),
		},
		WantQuotaCount:           0,
		WantLimitRangeCount:      3,
		WantNamespacesWithQuotas: 0,
		WantLRKeys:               []string{"apps/a-limits", "apps/b-limits", "web/z-limits"},
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

			if diff := cmp.Diff(test.WantQuotaCount, data.QuotaCount); diff != "" {
				t.Errorf("quota count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantLimitRangeCount, data.LimitRangeCount); diff != "" {
				t.Errorf("limit range count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNamespacesWithQuotas, data.NamespacesWithQuotas); diff != "" {
				t.Errorf("namespaces with quotas mismatch (-want +got):\n%s", diff)
			}
			if len(test.WantLRKeys) > 0 {
				var keys []string
				for _, lr := range data.LimitRanges {
					keys = append(keys, lr.Namespace+"/"+lr.Name)
				}
				if diff := cmp.Diff(test.WantLRKeys, keys); diff != "" {
					t.Errorf("limit range order mismatch (-want +got):\n%s", diff)
				}
			}
			if test.WantFirstQuotaNS == "" {
				return
			}
			if len(data.Quotas) == 0 {
				t.Fatal("expected at least one quota")
			}
			first := data.Quotas[0]
			if diff := cmp.Diff(test.WantFirstQuotaNS, first.Namespace); diff != "" {
				t.Errorf("first quota namespace mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstQuotaName, first.Name); diff != "" {
				t.Errorf("first quota name mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstHard, first.Hard, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("first quota hard mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstUsed, first.Used, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("first quota used mismatch (-want +got):\n%s", diff)
			}
			if len(data.LimitRanges) > 0 {
				got := data.LimitRanges[0].ItemCount
				if diff := cmp.Diff(test.WantFirstLRItemCount, got); diff != "" {
					t.Errorf("first limit range item count mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name     string
		Resource string
		Want     error
	}{{ // Test 0: ResourceQuota list failure is wrapped with ErrScan.
		Name:     "quotas list fails",
		Resource: "resourcequotas",
		Want:     scanner.ErrScan,
	}, { // Test 1: LimitRange list failure is wrapped with ErrScan.
		Name:     "limit ranges list fails",
		Resource: "limitranges",
		Want:     scanner.ErrScan,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset()
			cs.PrependReactor("list", test.Resource,
				func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errBoom
				})
			client := kube.NewTestClientWithClientset("test", cs)

			_, err := NewScanner().Scan(context.Background(), client)
			if !errors.Is(err, test.Want) {
				t.Fatalf("expected error %v, got %v", test.Want, err)
			}
			if !errors.Is(err, errBoom) {
				t.Fatalf("expected wrapped %v, got %v", errBoom, err)
			}
		})
	}
}
