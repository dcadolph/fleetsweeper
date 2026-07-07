package ingress

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// errBoom is a sentinel error injected into fake client reactors.
var errBoom = errors.New("boom")

// ingress builds an Ingress with the given class, TLS flag, and host rules.
// An empty class leaves IngressClassName unset. Each host becomes one rule,
// so passing an empty host exercises the scanner's empty-host skip.
func ingress(namespace, name, class string, tls bool, hosts ...string) *networkingv1.Ingress {
	spec := networkingv1.IngressSpec{}
	if class != "" {
		spec.IngressClassName = &class
	}
	for _, h := range hosts {
		spec.Rules = append(spec.Rules, networkingv1.IngressRule{Host: h})
	}
	if tls {
		spec.TLS = []networkingv1.IngressTLS{{Hosts: hosts}}
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       spec,
	}
}

func TestNewScanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name           string
		WantFirstNS    string
		WantFirstName  string
		WantFirstClass string
		WantFirstHosts []string
		Objects        []runtime.Object
		WantCount      int
		WantFirstTLS   bool
	}{{ // Test 0: Empty cluster reports zero ingresses.
		Name:      "empty",
		Objects:   nil,
		WantCount: 0,
	}, { // Test 1: Two ingresses sort by namespace then name.
		Name: "two ingresses sorted",
		Objects: []runtime.Object{
			ingress("web", "api", "", false, "c.example.com"),
			ingress("apps", "web", "nginx", true, "a.example.com", "b.example.com"),
		},
		WantCount:      2,
		WantFirstNS:    "apps",
		WantFirstName:  "web",
		WantFirstClass: "nginx",
		WantFirstHosts: []string{"a.example.com", "b.example.com"},
		WantFirstTLS:   true,
	}, { // Test 2: Ingress with no class, no TLS, and no rules has nil hosts.
		Name: "bare ingress",
		Objects: []runtime.Object{
			ingress("apps", "bare", "", false),
		},
		WantCount:      1,
		WantFirstNS:    "apps",
		WantFirstName:  "bare",
		WantFirstClass: "",
		WantFirstHosts: nil,
		WantFirstTLS:   false,
	}, { // Test 3: Empty host rules are skipped, only real hosts are kept.
		Name: "empty host skipped",
		Objects: []runtime.Object{
			ingress("apps", "mixed", "", false, "", "real.example.com"),
		},
		WantCount:      1,
		WantFirstNS:    "apps",
		WantFirstName:  "mixed",
		WantFirstClass: "",
		WantFirstHosts: []string{"real.example.com"},
		WantFirstTLS:   false,
	}, { // Test 4: Two ingresses in one namespace sort by name.
		Name: "same namespace sorts by name",
		Objects: []runtime.Object{
			ingress("apps", "z-ing", "", false, "z.example.com"),
			ingress("apps", "a-ing", "", false, "a.example.com"),
		},
		WantCount:      2,
		WantFirstNS:    "apps",
		WantFirstName:  "a-ing",
		WantFirstClass: "",
		WantFirstHosts: []string{"a.example.com"},
		WantFirstTLS:   false,
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
			if test.WantFirstNS == "" {
				return
			}
			if len(data.Ingresses) == 0 {
				t.Fatal("expected at least one ingress")
			}
			first := data.Ingresses[0]
			if diff := cmp.Diff(test.WantFirstNS, first.Namespace); diff != "" {
				t.Errorf("first ingress namespace mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstName, first.Name); diff != "" {
				t.Errorf("first ingress name mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstClass, first.IngressClassName); diff != "" {
				t.Errorf("first ingress class mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstHosts, first.Hosts, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("first ingress hosts mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantFirstTLS, first.TLS); diff != "" {
				t.Errorf("first ingress tls mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewScannerListError(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.PrependReactor("list", "ingresses",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errBoom
		})
	client := kube.NewTestClientWithClientset("test", cs)

	_, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("expected error %v, got %v", scanner.ErrScan, err)
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped %v, got %v", errBoom, err)
	}
}
