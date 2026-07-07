package deprecatedapis

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// cronJob builds an unstructured batch/v1beta1 CronJob for the dynamic fake.
func cronJob(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "batch/v1beta1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}}
}

// TestNilDynamicClient verifies the scanner reports the server version and
// stops cleanly when no dynamic client is available (nothing to enumerate).
func TestNilDynamicClient(t *testing.T) {
	t.Parallel()

	cs := fakeclientset.NewSimpleClientset()
	cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.24.0"}
	client := kube.NewTestClientWithClientset("test", cs)

	result, err := NewScanner().Scan(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := result.Data.(Data)

	if diff := cmp.Diff("v1.24.0", data.ServerVersion); diff != "" {
		t.Errorf("server version mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(0, len(data.Deprecated)); diff != "" {
		t.Errorf("expected no deprecated entries (-want +got):\n%s", diff)
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
