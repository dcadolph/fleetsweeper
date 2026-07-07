package networkpolicy

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// ns builds a Namespace object.
func ns(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// np builds a NetworkPolicy with the given policy types and rule counts.
func np(namespace, name string, types []networkingv1.PolicyType, ingress, egress int) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: types,
			Ingress:     make([]networkingv1.NetworkPolicyIngressRule, ingress),
			Egress:      make([]networkingv1.NetworkPolicyEgressRule, egress),
		},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name                 string
		Objects              []runtime.Object
		WantCount            int
		WantNamespacesWith   int
		WantNamespacesNot    int
		WantFirstNamespace   string
		WantFirstPolicyTypes []string
		WantFirstIngress     int
		WantFirstEgress      int
	}{{ // Test 0: No policies, three namespaces all uncovered.
		Name:               "no policies",
		Objects:            []runtime.Object{ns("default"), ns("kube-system"), ns("apps")},
		WantCount:          0,
		WantNamespacesWith: 0,
		WantNamespacesNot:  3,
	}, { // Test 1: One policy covers one of two namespaces.
		Name: "one covered one bare",
		Objects: []runtime.Object{
			ns("apps"), ns("bare"),
			np("apps", "deny-all", []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, 0, 0),
		},
		WantCount:            1,
		WantNamespacesWith:   1,
		WantNamespacesNot:    1,
		WantFirstNamespace:   "apps",
		WantFirstPolicyTypes: []string{"Ingress"},
	}, { // Test 2: Two policies in one namespace count once for coverage.
		Name: "two policies one namespace",
		Objects: []runtime.Object{
			ns("apps"),
			np("apps", "allow-egress", []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, 0, 2),
			np("apps", "deny-ingress", []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, 3, 0),
		},
		WantCount:            2,
		WantNamespacesWith:   1,
		WantNamespacesNot:    0,
		WantFirstNamespace:   "apps",
		WantFirstPolicyTypes: []string{"Egress"},
		WantFirstEgress:      2,
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

			if diff := cmp.Diff(test.WantCount, data.Count); diff != "" {
				t.Errorf("count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNamespacesWith, data.NamespacesWithPolicies); diff != "" {
				t.Errorf("namespaces with policies mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantNamespacesNot, data.NamespacesWithoutPolicies); diff != "" {
				t.Errorf("namespaces without policies mismatch (-want +got):\n%s", diff)
			}
			if test.WantFirstNamespace == "" {
				return
			}
			if len(data.Policies) == 0 {
				t.Fatal("expected at least one policy")
			}
			first := data.Policies[0]
			if diff := cmp.Diff(test.WantFirstNamespace, first.Namespace); diff != "" {
				t.Errorf("first policy namespace mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstPolicyTypes, first.PolicyTypes); diff != "" {
				t.Errorf("first policy types mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstEgress, first.EgressRuleCount); diff != "" {
				t.Errorf("first policy egress count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
