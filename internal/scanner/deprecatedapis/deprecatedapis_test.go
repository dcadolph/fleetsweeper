package deprecatedapis

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// cronJob builds an unstructured batch/v1beta1 CronJob for the dynamic fake.
func cronJob(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "batch/v1beta1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}}
}

// TestNilDynamicClient verifies the scanner errors when no dynamic client is available, since
// nothing could be probed and an empty result would read as a cluster with no deprecated APIs.
func TestNilDynamicClient(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if !errors.Is(err, scanner.ErrScan) {
		t.Fatalf("err = %v, want %v", err, scanner.ErrScan)
	}
	if result.Data != nil {
		t.Errorf("data = %v, want none", result.Data)
	}
}

// TestScanListErrors verifies failed discovery and failed probes are classified instead of read
// as a cluster with no deprecated APIs in use.
func TestScanListErrors(t *testing.T) {
	t.Parallel()
	gvr := schema.GroupVersionResource{Group: "batch", Version: "v1beta1", Resource: "cronjobs"}
	forbidden := apierrors.NewForbidden(gvr.GroupResource(), "", errors.New("rbac denied"))
	tests := []struct {
		DiscoveryErr  error
		ProbeErr      error
		Want          error
		WantState     scanner.State
		WantForbidden bool
	}{{ // Test 0: Failed discovery errors the scan, since no version can be checked.
		DiscoveryErr: errors.New("discovery down"), Want: scanner.ErrScan, WantState: scanner.StateErrored,
	}, { // Test 1: The only probe denied errors the scan.
		ProbeErr: forbidden, Want: scanner.ErrScan, WantState: scanner.StateErrored,
	}, { // Test 2: A version gone between discovery and probe is skipped, not observed.
		ProbeErr: apierrors.NewNotFound(gvr.GroupResource(), ""), WantState: scanner.StateOK,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fakeclientset.NewSimpleClientset()
			cs.Resources = []*metav1.APIResourceList{{GroupVersion: "batch/v1beta1"}, {GroupVersion: "v1"}}
			if test.DiscoveryErr != nil {
				cs.PrependReactor("get", "group", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.DiscoveryErr
				})
			}
			scheme := runtime.NewScheme()
			dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
				map[schema.GroupVersionResource]string{gvr: "CronJobList"}, cronJob("nightly"))
			if test.ProbeErr != nil {
				dyn.PrependReactor("list", "cronjobs", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.ProbeErr
				})
			}
			result, err := NewScanner().Scan(context.Background(), kube.NewTestClientWithDynamic("test", cs, dyn))
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if result.State != test.WantState {
				t.Errorf("state = %q, want %q", result.State, test.WantState)
			}
		})
	}
}

// TestServedDeprecatedAPICounted verifies a deprecated API that is still served
// and has live instances is reported with an accurate instance count, while
// deprecated APIs the server does not serve are skipped.
func TestServedDeprecatedAPICounted(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.Resources = []*metav1.APIResourceList{{GroupVersion: "batch/v1beta1"}}
	cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.24.0"}

	gvr := schema.GroupVersionResource{Group: "batch", Version: "v1beta1", Resource: "cronjobs"}
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{gvr: "CronJobList"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, cronJob("nightly"), cronJob("hourly"))

	client := kube.NewTestClientWithDynamic("test", cs, dyn)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := result.Data.(Data)

	if diff := cmp.Diff(1, len(data.Deprecated)); diff != "" {
		t.Fatalf("expected one deprecated entry (-want +got):\n%s", diff)
	}
	entry := data.Deprecated[0]
	if diff := cmp.Diff("batch/v1beta1", entry.APIVersion); diff != "" {
		t.Errorf("api version mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("CronJob", entry.Kind); diff != "" {
		t.Errorf("kind mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(2, entry.InstanceCount); diff != "" {
		t.Errorf("instance count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(2, data.TotalInstances); diff != "" {
		t.Errorf("total instances mismatch (-want +got):\n%s", diff)
	}
}
