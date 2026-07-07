package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/testcerts"
)

// serviceRef builds a webhook client config pointing at namespace/name with an
// optional CA bundle.
func serviceRef(namespace, name string, caBundle []byte) admissionregv1.WebhookClientConfig {
	return admissionregv1.WebhookClientConfig{
		Service:  &admissionregv1.ServiceReference{Namespace: namespace, Name: name},
		CABundle: caBundle,
	}
}

// mutating builds a MutatingWebhookConfiguration with one webhook.
func mutating(cfgName, whName string, cc admissionregv1.WebhookClientConfig, policy *admissionregv1.FailurePolicyType) *admissionregv1.MutatingWebhookConfiguration {
	return &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: cfgName},
		Webhooks: []admissionregv1.MutatingWebhook{{
			Name:          whName,
			ClientConfig:  cc,
			FailurePolicy: policy,
		}},
	}
}

// validating builds a ValidatingWebhookConfiguration with one webhook.
func validating(cfgName, whName string, cc admissionregv1.WebhookClientConfig, policy *admissionregv1.FailurePolicyType) *admissionregv1.ValidatingWebhookConfiguration {
	return &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: cfgName},
		Webhooks: []admissionregv1.ValidatingWebhook{{
			Name:          whName,
			ClientConfig:  cc,
			FailurePolicy: policy,
		}},
	}
}

// readyEndpoints builds an Endpoints object with one ready address.
func readyEndpoints(namespace, name string) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	fail := admissionregv1.Fail
	ignore := admissionregv1.Ignore

	expiringCA, err := testcerts.PEMWithExpiry("soon", time.Now().Add(10*24*time.Hour+time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tests := []struct {
		Name                  string
		Objects               []runtime.Object
		WantTotal             int
		WantUnhealthy         int
		WantExpiringCABundles int
		WantFailClosed        int
	}{{ // Test 0: Healthy service, ignore policy, no CA. Nothing flagged.
		Name: "healthy ignore",
		Objects: []runtime.Object{
			mutating("mwc", "m.example.com", serviceRef("webhooks", "svc", nil), &ignore),
			readyEndpoints("webhooks", "svc"),
		},
		WantTotal: 1,
	}, { // Test 1: Service with no endpoints is unhealthy.
		Name: "missing endpoints",
		Objects: []runtime.Object{
			mutating("mwc", "m.example.com", serviceRef("webhooks", "svc", nil), &ignore),
		},
		WantTotal:     1,
		WantUnhealthy: 1,
	}, { // Test 2: failurePolicy=Fail counts as fail-closed.
		Name: "fail closed",
		Objects: []runtime.Object{
			mutating("mwc", "m.example.com", serviceRef("webhooks", "svc", nil), &fail),
			readyEndpoints("webhooks", "svc"),
		},
		WantTotal:      1,
		WantFailClosed: 1,
	}, { // Test 3: CA bundle expiring within the window is flagged.
		Name: "expiring ca",
		Objects: []runtime.Object{
			mutating("mwc", "m.example.com", serviceRef("webhooks", "svc", expiringCA), &ignore),
			readyEndpoints("webhooks", "svc"),
		},
		WantTotal:             1,
		WantExpiringCABundles: 1,
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

			if diff := cmp.Diff(test.WantTotal, data.TotalWebhooks); diff != "" {
				t.Errorf("total webhooks mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantUnhealthy, data.UnhealthyWebhooks); diff != "" {
				t.Errorf("unhealthy mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantExpiringCABundles, data.ExpiringCABundles); diff != "" {
				t.Errorf("expiring CA bundles mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFailClosed, data.FailClosedWebhooks); diff != "" {
				t.Errorf("fail-closed mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNewScannerDegraded verifies that a failed webhook list marks the result
// degraded, names the failing list in the reason, and still returns the
// webhooks collected from the list that succeeded.
func TestNewScannerDegraded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name           string
		Objects        []runtime.Object
		WantReasons    []string
		WantTotal      int
		FailMutating   bool
		FailValidating bool
	}{{ // Test 0: Mutating list fails; validating webhooks still counted.
		Name:         "mutating fails",
		Objects:      []runtime.Object{validating("vwc", "v.example.com", serviceRef("webhooks", "svc", nil), nil)},
		FailMutating: true,
		WantTotal:    1,
		WantReasons:  []string{"mutating webhook list failed"},
	}, { // Test 1: Validating list fails; mutating webhooks still counted.
		Name:           "validating fails",
		Objects:        []runtime.Object{mutating("mwc", "m.example.com", serviceRef("webhooks", "svc", nil), nil)},
		FailValidating: true,
		WantTotal:      1,
		WantReasons:    []string{"validating webhook list failed"},
	}, { // Test 2: Both lists fail; no webhooks and both reasons present.
		Name:           "both fail",
		FailMutating:   true,
		FailValidating: true,
		WantTotal:      0,
		WantReasons:    []string{"mutating webhook list failed", "validating webhook list failed"},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			cs := fakeclientset.NewSimpleClientset(test.Objects...)
			if test.FailMutating {
				cs.PrependReactor("list", "mutatingwebhookconfigurations", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("boom")
				})
			}
			if test.FailValidating {
				cs.PrependReactor("list", "validatingwebhookconfigurations", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("boom")
				})
			}
			client := kube.NewTestClientWithClientset("test", cs)

			result, err := NewScanner().Scan(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(scanner.StateDegraded, result.State); diff != "" {
				t.Errorf("state mismatch (-want +got):\n%s", diff)
			}
			for _, want := range test.WantReasons {
				if !strings.Contains(result.Reason, want) {
					t.Errorf("reason %q missing %q", result.Reason, want)
				}
			}
			data, ok := result.Data.(Data)
			if !ok {
				t.Fatalf("expected Data type, got %T", result.Data)
			}
			if diff := cmp.Diff(test.WantTotal, data.TotalWebhooks); diff != "" {
				t.Errorf("total webhooks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
