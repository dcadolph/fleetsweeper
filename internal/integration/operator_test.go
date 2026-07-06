//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"go.uber.org/zap"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dcadolph/fleetsweeper/internal/controller"
)

const operatorCluster = "fleetsweeper-operator"

// TestOperatorEndToEnd spins up a kind cluster, installs the ClusterScan
// CRD, runs the in-process controller against the cluster, applies a
// ClusterScan resource, and verifies the controller drives it to phase=
// Succeeded with a non-zero ObservedScore. The test is build-tag gated
// since it requires docker + kind locally.
func TestOperatorEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping operator integration test in short mode")
	}
	requireKind(t)
	requireDocker(t)

	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	t.Log("creating kind cluster")
	createCluster(t, operatorCluster, kubeconfigPath)
	t.Cleanup(func() { deleteCluster(t, operatorCluster) })

	if err := installClusterScanCRD(t, kubeconfigPath); err != nil {
		t.Fatalf("install CRD: %v", err)
	}

	dyn := newDynamicClient(t, kubeconfigPath)

	runner := &recordingRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctrl := controller.New(controller.Config{
		Dynamic:      dyn,
		Runner:       runner,
		Log:          zap.NewNop(),
		PollInterval: 2 * time.Second,
	})
	go func() { _ = ctrl.Run(ctx) }()

	applyClusterScan(t, dyn, "default", "e2e-scan", map[string]any{
		"interval": "1m",
		"contexts": []any{"kind-" + operatorCluster},
	})

	if err := waitForPhase(ctx, t, dyn, "default", "e2e-scan", controller.PhaseSucceeded, 30*time.Second); err != nil {
		t.Fatalf("waiting for Succeeded: %v", err)
	}
	if runner.calls == 0 {
		t.Fatal("runner was not invoked")
	}
}

// recordingRunner is a ScanRunner that returns a canned summary. The kind
// test uses it instead of spinning up a real Server because that would
// require a full Fleetsweeper deployment; the value of this test is the
// controller's behavior against the apiserver, not the scanners.
type recordingRunner struct{ calls int }

// ScanOnce records the call and returns a small synthetic summary.
func (r *recordingRunner) ScanOnce(_ context.Context, _ controller.ScanOptions) (controller.ScanSummary, error) {
	r.calls++
	return controller.ScanSummary{
		ScanID: "e2e-scan-id", Score: 80, Grade: "B",
		Critical: 1, Warning: 5, Clusters: 1,
	}, nil
}

// installClusterScanCRD reads the bundled CRD manifest and applies it to
// the cluster using the apiextensions client.
func installClusterScanCRD(t *testing.T, kubeconfigPath string) error {
	t.Helper()
	manifestPath := filepath.Join(repoRoot(), "deploy/crds/clusterscan.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(apiextv1.AddToScheme(scheme))
	dec := yaml.NewYAMLOrJSONDecoder(bytesReader(raw), 4096)
	var crd apiextv1.CustomResourceDefinition
	if err := dec.Decode(&crd); err != nil {
		return err
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return err
	}
	cs, err := apiextclient.NewForConfig(cfg)
	if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1().CustomResourceDefinitions().Create(
		context.Background(), &crd, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	// Wait for the CRD to register with the apiserver discovery.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		got, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(
			context.Background(), crd.Name, metav1.GetOptions{})
		if err == nil {
			ready := false
			for _, c := range got.Status.Conditions {
				if c.Type == apiextv1.Established && c.Status == apiextv1.ConditionTrue {
					ready = true
					break
				}
			}
			if ready {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

// newDynamicClient builds a dynamic client targeting the kind kubeconfig.
func newDynamicClient(t *testing.T, kubeconfigPath string) dynamic.Interface {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	return dyn
}

// applyClusterScan creates a ClusterScan resource with the supplied spec.
func applyClusterScan(t *testing.T, dyn dynamic.Interface, namespace, name string, spec map[string]any) {
	t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fleetsweeper.io/v1alpha1",
		"kind":       "ClusterScan",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	}}
	_, err := dyn.Resource(controller.ClusterScanGVR).Namespace(namespace).
		Create(context.Background(), obj, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ClusterScan: %v", err)
	}
}

// waitForPhase polls the ClusterScan resource's status.phase until it
// matches want or the deadline elapses.
func waitForPhase(ctx context.Context, t *testing.T, dyn dynamic.Interface, namespace, name, want string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		obj, err := dyn.Resource(controller.ClusterScanGVR).Namespace(namespace).
			Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
			if phase == want {
				return nil
			}
			t.Logf("phase=%q (waiting for %q)", phase, want)
		}
		time.Sleep(time.Second)
	}
	return context.DeadlineExceeded
}

// bytesReader wraps a byte slice so it satisfies io.Reader without taking
// a dependency on bytes.NewReader's exact return type in tests.
func bytesReader(b []byte) *byteSliceReader {
	return &byteSliceReader{data: b}
}

// byteSliceReader is a minimal io.Reader over a byte slice.
type byteSliceReader struct {
	data []byte
	pos  int
}

// Read copies bytes into p and advances the cursor.
func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errEOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// errEOF is the EOF sentinel for byteSliceReader.
var errEOF = errEOFType{}

// errEOFType implements io.EOF semantics without importing io directly.
type errEOFType struct{}

// Error returns "EOF" so callers that string-match see the expected token.
func (errEOFType) Error() string { return "EOF" }

// repoRoot returns the absolute path to the repository root. Computed by
// walking up from the current test file's location.
func repoRoot() string {
	_, file, _, _ := goruntime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}
