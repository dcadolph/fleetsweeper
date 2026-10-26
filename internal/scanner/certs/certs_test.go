package certs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/testcerts"
)

// tlsSecret builds a TLS Secret whose tls.crt expires daysFromNow days out.
func tlsSecret(t *testing.T, name string, daysFromNow int) *corev1.Secret {
	t.Helper()
	// A one-hour buffer keeps the hours/24 truncation on the intended side of
	// each bucket boundary regardless of when the test runs.
	notAfter := time.Now().Add(time.Duration(daysFromNow)*24*time.Hour + time.Hour)
	pemBytes, err := testcerts.PEMWithExpiry(name, notAfter)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemBytes},
	}
}

// opaqueSecret builds a non-TLS Secret that the scanner must ignore.
func opaqueSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"tls.crt": []byte("not a cert")},
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		Objects      []runtime.Object
		WantTotal    int
		WantCritical int
		WantWarning  int
		WantInfo     int
		WantSoonest  int
	}{{ // Test 0: No secrets, soonest sentinel stays -1.
		Name:        "empty",
		WantTotal:   0,
		WantSoonest: -1,
	}, { // Test 1: One cert in each severity bucket plus a healthy one.
		Name: "one per bucket",
		Objects: []runtime.Object{
			tlsSecret(t, "crit", 3),
			tlsSecret(t, "warn", 20),
			tlsSecret(t, "info", 60),
			tlsSecret(t, "healthy", 200),
		},
		WantTotal:    4,
		WantCritical: 1,
		WantWarning:  1,
		WantInfo:     1,
		WantSoonest:  3,
	}, { // Test 2: Opaque secrets are ignored even when they carry a tls.crt key.
		Name: "opaque ignored",
		Objects: []runtime.Object{
			opaqueSecret("bogus"),
			tlsSecret(t, "real", 45),
		},
		WantTotal:   1,
		WantInfo:    1,
		WantSoonest: 45,
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

			if diff := cmp.Diff(test.WantTotal, data.TotalCerts); diff != "" {
				t.Errorf("total certs mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantCritical, data.Critical); diff != "" {
				t.Errorf("critical mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantWarning, data.Warning); diff != "" {
				t.Errorf("warning mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantInfo, data.Info); diff != "" {
				t.Errorf("info mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantSoonest, data.Soonest); diff != "" {
				t.Errorf("soonest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestWebhookCABundles verifies caBundle expiry is inspected on mutating and
// validating webhook configurations, not just TLS secrets.
func TestWebhookCABundles(t *testing.T) {
	t.Parallel()

	notAfter := time.Now().Add(10*24*time.Hour + time.Hour)
	caPEM, err := testcerts.PEMWithExpiry("webhook-ca", notAfter)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	mwc := &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "mwc"},
		Webhooks: []admissionregv1.MutatingWebhook{{
			Name:         "m.example.com",
			ClientConfig: admissionregv1.WebhookClientConfig{CABundle: caPEM},
		}},
	}
	vwc := &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc"},
		Webhooks: []admissionregv1.ValidatingWebhook{{
			Name:         "v.example.com",
			ClientConfig: admissionregv1.WebhookClientConfig{CABundle: caPEM},
		}},
	}

	cs := fakeclientset.NewSimpleClientset(mwc, vwc)
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := result.Data.(Data)

	if diff := cmp.Diff(2, data.TotalCerts); diff != "" {
		t.Errorf("total certs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(10, data.Soonest); diff != "" {
		t.Errorf("soonest mismatch (-want +got):\n%s", diff)
	}
}

// webhookPair returns mutating and validating webhook configurations whose caBundles expire in
// ten days.
func webhookPair(t *testing.T) (*admissionregv1.MutatingWebhookConfiguration, *admissionregv1.ValidatingWebhookConfiguration) {
	t.Helper()
	caPEM, err := testcerts.PEMWithExpiry("webhook-ca", time.Now().Add(10*24*time.Hour+time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	mwc := &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "mwc"},
		Webhooks: []admissionregv1.MutatingWebhook{{
			Name: "m.example.com", ClientConfig: admissionregv1.WebhookClientConfig{CABundle: caPEM},
		}},
	}
	vwc := &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc"},
		Webhooks: []admissionregv1.ValidatingWebhook{{
			Name: "v.example.com", ClientConfig: admissionregv1.WebhookClientConfig{CABundle: caPEM},
		}},
	}
	return mwc, vwc
}

// TestScanForbidden verifies denied lists never read as a cluster with zero certificates: one
// denied list degrades the result and keeps the rest, and every list denied errors.
func TestScanForbidden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Denied     []string
		Want       error
		WantState  scanner.State
		WantTotal  int
		WantReason string
	}{{ // Test 0: Secrets denied, webhooks read: degraded with the two webhook certs.
		Denied: []string{"secrets"}, WantState: scanner.StateDegraded, WantTotal: 2,
		WantReason: "secrets: forbidden: ",
	}, { // Test 1: Every list denied: errored with no data, not degraded with zero certs.
		Denied:    []string{"secrets", "mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
		Want:      scanner.ErrScan,
		WantState: scanner.StateErrored, WantReason: "secrets: forbidden: ",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			mwc, vwc := webhookPair(t)
			cs := fakeclientset.NewSimpleClientset(tlsSecret(t, "crit", 3), mwc, vwc)
			for _, resource := range test.Denied {
				cs.PrependReactor("list", resource, func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "",
						errors.New("rbac denied"))
				})
			}
			result, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithClientset("test", cs))
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if result.State != test.WantState {
				t.Errorf("state = %q, want %q", result.State, test.WantState)
			}
			if len(result.Reason) < len(test.WantReason) || result.Reason[:len(test.WantReason)] != test.WantReason {
				t.Errorf("reason = %q, want prefix %q", result.Reason, test.WantReason)
			}
			if test.WantState == scanner.StateErrored {
				if result.Data != nil {
					t.Errorf("errored result carries data %+v", result.Data)
				}
				return
			}
			if got := result.Data.(Data).TotalCerts; got != test.WantTotal {
				t.Errorf("total certs = %d, want %d", got, test.WantTotal)
			}
		})
	}
}

// TestSecretListSelectsTLS verifies the Secret list asks the apiserver for TLS Secrets only.
func TestSecretListSelectsTLS(t *testing.T) {
	t.Parallel()
	cs := fakeclientset.NewSimpleClientset()
	var got []string
	cs.PrependReactor("list", "secrets", func(a clienttesting.Action) (bool, runtime.Object, error) {
		got = append(got, a.(clienttesting.ListActionImpl).GetListOptions().FieldSelector)
		return false, nil, nil
	})
	if _, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithClientset("test", cs)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if diff := cmp.Diff([]string{"type=kubernetes.io/tls"}, got); diff != "" {
		t.Errorf("secret field selectors mismatch (-want +got):\n%s", diff)
	}
}
