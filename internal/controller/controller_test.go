package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// fakeRunner is a ScanRunner test double that records every invocation and
// returns a canned summary or error.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []ScanOptions
	summary ScanSummary
	err     error
}

// ScanOnce records the call and returns the configured response.
func (f *fakeRunner) ScanOnce(_ context.Context, opts ScanOptions) (ScanSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, opts)
	return f.summary, f.err
}

// callCount returns the number of times ScanOnce was invoked.
func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestControllerMetricsRecord verifies the package-level counters move on
// successful reconciliation and that ResetMetrics zeroes them.
func TestControllerMetricsRecord(t *testing.T) {
	ResetMetrics()
	dyn, _ := newFakeDynamic(t,
		newClusterScan("default", "metrics-test", map[string]any{
			"interval": "15m",
			"contexts": []any{"a"},
		}),
	)
	runner := &fakeRunner{summary: ScanSummary{ScanID: "m1", Score: 75, Grade: "C", Clusters: 1}}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: nopLogger()})
	reconcileOne(t, c, dyn, "default", "metrics-test")

	if reconcileTotal.Load() != 1 {
		t.Errorf("reconcileTotal: want 1, got %d", reconcileTotal.Load())
	}
	if scansTriggered.Load() != 1 {
		t.Errorf("scansTriggered: want 1, got %d", scansTriggered.Load())
	}
	if scansSucceeded.Load() != 1 {
		t.Errorf("scansSucceeded: want 1, got %d", scansSucceeded.Load())
	}
	ResetMetrics()
	if reconcileTotal.Load() != 0 {
		t.Errorf("Reset did not zero counters")
	}
}

// nopLogger returns a zap logger that drops everything; saves the
// boilerplate in metrics-related tests.
func nopLogger() *zap.Logger { return zap.NewNop() }

// TestReconcileDueScanFires verifies a never-scanned resource triggers a scan
// on first reconciliation and its status is updated.
func TestReconcileDueScanFires(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("default", "prod", map[string]any{
			"interval": "15m",
			"contexts": []any{"prod-east", "prod-west"},
		}),
	)
	runner := &fakeRunner{summary: ScanSummary{
		ScanID: "scan-1", Score: 88, Grade: "B",
		Critical: 1, Warning: 4, Clusters: 2,
	}}
	c := New(Config{
		Dynamic:      dyn,
		Runner:       runner,
		Log:          zap.NewNop(),
		PollInterval: time.Second,
	})

	reconcileOne(t, c, dyn, "default", "prod")

	if runner.callCount() != 1 {
		t.Fatalf("want 1 scan invocation, got %d", runner.callCount())
	}
	if runner.calls[0].Contexts[0] != "prod-east" {
		t.Errorf("unexpected contexts: %v", runner.calls[0].Contexts)
	}

	obj, err := dyn.Resource(gvr).Namespace("default").Get(context.Background(), "prod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cr: %v", err)
	}
	status := readStatus(obj)
	if status.Phase != PhaseSucceeded {
		t.Errorf("phase: want Succeeded, got %s", status.Phase)
	}
	if status.LastScanID != "scan-1" {
		t.Errorf("LastScanID: want scan-1, got %s", status.LastScanID)
	}
	if status.ObservedScore != 88 {
		t.Errorf("score: want 88, got %d", status.ObservedScore)
	}
}

// TestReconcilePausedSkips verifies spec.paused is honored.
func TestReconcilePausedSkips(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("default", "paused-scan", map[string]any{
			"interval": "15m",
			"contexts": []any{"a"},
			"paused":   true,
		}),
	)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "default", "paused-scan")

	if runner.callCount() != 0 {
		t.Errorf("paused resource should not trigger a scan, got %d calls", runner.callCount())
	}
	obj, _ := dyn.Resource(gvr).Namespace("default").Get(context.Background(), "paused-scan", metav1.GetOptions{})
	if readStatus(obj).Phase != PhasePaused {
		t.Errorf("phase: want Paused, got %s", readStatus(obj).Phase)
	}
}

// TestReconcileNotYetDueSkips verifies a recently-scanned resource is not
// re-fired before its interval elapses.
func TestReconcileNotYetDueSkips(t *testing.T) {
	t.Parallel()
	recent := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	obj := newClusterScan("default", "recent", map[string]any{
		"interval": "1h",
		"contexts": []any{"a"},
	})
	unstructured.SetNestedField(obj.Object, recent, "status", "lastScanTime")

	dyn, _ := newFakeDynamic(t, obj)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "default", "recent")

	if runner.callCount() != 0 {
		t.Errorf("not-yet-due resource should not scan, got %d calls", runner.callCount())
	}
}

// TestReconcileFailedScanRecordsPhase verifies a scan error surfaces in status.
func TestReconcileFailedScanRecordsPhase(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("default", "doomed", map[string]any{
			"interval": "15m",
			"contexts": []any{"unreachable"},
		}),
	)
	runner := &fakeRunner{err: errors.New("no clusters reachable")}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "default", "doomed")

	obj, _ := dyn.Resource(gvr).Namespace("default").Get(context.Background(), "doomed", metav1.GetOptions{})
	if readStatus(obj).Phase != PhaseFailed {
		t.Errorf("phase: want Failed, got %s", readStatus(obj).Phase)
	}
}

// TestReconcileInvalidIntervalRecordsFailure verifies bad interval is reported.
func TestReconcileInvalidIntervalRecordsFailure(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("default", "bad", map[string]any{
			"interval": "potato",
			"contexts": []any{"a"},
		}),
	)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "default", "bad")

	if runner.callCount() != 0 {
		t.Error("bad interval should not trigger a scan")
	}
	obj, _ := dyn.Resource(gvr).Namespace("default").Get(context.Background(), "bad", metav1.GetOptions{})
	if readStatus(obj).Phase != PhaseFailed {
		t.Errorf("phase: want Failed, got %s", readStatus(obj).Phase)
	}
}

// TestRunWatchTriggersScan verifies the informer path end to end: a resource
// created after the controller starts is reconciled from its watch event, well
// before the first poll tick.
func TestRunWatchTriggersScan(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t)
	runner := &fakeRunner{summary: ScanSummary{ScanID: "w1", Score: 90, Grade: "A", Clusters: 1}}
	c := New(Config{
		Dynamic:      dyn,
		Runner:       runner,
		Log:          zap.NewNop(),
		PollInterval: time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()

	obj := newClusterScan("default", "watched", map[string]any{
		"interval": "15m",
		"contexts": []any{"a"},
	})
	if _, err := dyn.Resource(gvr).Namespace("default").Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		cancel()
		t.Fatalf("create cr: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for runner.callCount() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("scan was not triggered by the watch event")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

// newClusterScan builds a minimal ClusterScan unstructured object with the
// supplied spec map.
func newClusterScan(namespace, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fleetsweeper.io/v1alpha1",
		"kind":       "ClusterScan",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": spec,
	}}
}

// reconcileOne fetches the named ClusterScan and reconciles it directly,
// standing in for the informer-driven path in Run.
func reconcileOne(t *testing.T, c *Controller, dyn dynamic.Interface, namespace, name string) {
	t.Helper()
	obj, err := dyn.Resource(ClusterScanGVR).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cr: %v", err)
	}
	c.reconcile(context.Background(), obj)
}

// newFakeDynamic returns a dynamic.Interface backed by a fake clientset
// pre-seeded with the supplied ClusterScan objects.
func newFakeDynamic(t *testing.T, objs ...*unstructured.Unstructured) (dynamic.Interface, schema.GroupVersionResource) {
	t.Helper()
	scheme := runtime.NewScheme()
	gvrToList := map[schema.GroupVersionResource]string{
		ClusterScanGVR: "ClusterScanList",
	}
	rtObjs := make([]runtime.Object, len(objs))
	for i, o := range objs {
		rtObjs[i] = o
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToList, rtObjs...)
	return dyn, ClusterScanGVR
}
