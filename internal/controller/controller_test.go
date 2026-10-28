package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// fakeRunner is a ScanRunner test double that records every invocation and
// returns a canned summary or error.
type fakeRunner struct {
	// mu guards every field below.
	mu sync.Mutex
	// calls records the options of every ScanOnce call.
	calls []ScanOptions
	// summary is returned on success.
	summary ScanSummary
	// err, when set, is returned instead of summary.
	err error
	// block, when set, makes ScanOnce wait for its context to end and record the cause.
	block bool
	// cause is the context cause a blocking ScanOnce observed.
	cause error
}

// ScanOnce records the call and returns the configured response.
func (f *fakeRunner) ScanOnce(ctx context.Context, opts ScanOptions) (ScanSummary, error) {
	f.mu.Lock()
	f.calls = append(f.calls, opts)
	block := f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		f.mu.Lock()
		f.cause = context.Cause(ctx)
		f.mu.Unlock()
		return ScanSummary{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.summary, f.err
}

// observedCause returns the cause a blocking ScanOnce recorded.
func (f *fakeRunner) observedCause() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cause
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
		newClusterScan("metrics-test", map[string]any{
			"interval": "15m",
			"contexts": []any{"a"},
		}),
	)
	runner := &fakeRunner{summary: ScanSummary{ScanID: "m1", Score: 75, Grade: "C", Clusters: 1}}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: nopLogger()})
	reconcileOne(t, c, dyn, "metrics-test")

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
		newClusterScan("prod", map[string]any{
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

	reconcileOne(t, c, dyn, "prod")

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
		newClusterScan("paused-scan", map[string]any{
			"interval": "15m",
			"contexts": []any{"a"},
			"paused":   true,
		}),
	)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "paused-scan")

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
	obj := newClusterScan("recent", map[string]any{
		"interval": "1h",
		"contexts": []any{"a"},
	})
	unstructured.SetNestedField(obj.Object, recent, "status", "lastScanTime")

	dyn, _ := newFakeDynamic(t, obj)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "recent")

	if runner.callCount() != 0 {
		t.Errorf("not-yet-due resource should not scan, got %d calls", runner.callCount())
	}
}

// TestReconcileFailedScanRecordsPhase verifies a scan error surfaces in status.
func TestReconcileFailedScanRecordsPhase(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("doomed", map[string]any{
			"interval": "15m",
			"contexts": []any{"unreachable"},
		}),
	)
	runner := &fakeRunner{err: errors.New("no clusters reachable")}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "doomed")

	obj, _ := dyn.Resource(gvr).Namespace("default").Get(context.Background(), "doomed", metav1.GetOptions{})
	if readStatus(obj).Phase != PhaseFailed {
		t.Errorf("phase: want Failed, got %s", readStatus(obj).Phase)
	}
}

// TestReconcileInvalidIntervalRecordsFailure verifies bad interval is reported.
func TestReconcileInvalidIntervalRecordsFailure(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t,
		newClusterScan("bad", map[string]any{
			"interval": "potato",
			"contexts": []any{"a"},
		}),
	)
	runner := &fakeRunner{}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})

	reconcileOne(t, c, dyn, "bad")

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

	obj := newClusterScan("watched", map[string]any{
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

// testNamespace is the namespace every test ClusterScan lives in.
const testNamespace = "default"

// newClusterScan builds a minimal ClusterScan unstructured object in testNamespace with the
// supplied spec map.
func newClusterScan(name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "fleetsweeper.io/v1alpha1",
		"kind":       "ClusterScan",
		"metadata": map[string]any{
			"namespace": testNamespace,
			"name":      name,
		},
		"spec": spec,
	}}
}

// reconcileOne fetches the named ClusterScan and reconciles it directly,
// standing in for the informer-driven path in Run.
func reconcileOne(t *testing.T, c *Controller, dyn dynamic.Interface, name string) {
	t.Helper()
	obj, err := dyn.Resource(ClusterScanGVR).Namespace(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
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

// getClusterScan reads the named ClusterScan back from the fake client.
func getClusterScan(t *testing.T, dyn dynamic.Interface, name string) *unstructured.Unstructured {
	t.Helper()
	obj, err := dyn.Resource(ClusterScanGVR).Namespace(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cr: %v", err)
	}
	return obj
}

// startController runs c until the test ends and returns once Run has returned on cleanup.
func startController(t *testing.T, c *Controller) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-runDone; err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	})
}

// waitForCalls polls until runner has seen at least n calls or two seconds pass.
func waitForCalls(t *testing.T, runner *fakeRunner, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runner.callCount() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d scans, saw %d", n, runner.callCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// drainEvents returns every event the fake recorder has buffered.
func drainEvents(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// TestFailingScanNotRerunWithinPoll verifies a failed scan waits out its retry delay instead of
// re-running on every poll tick, and that the failure is recorded in status and conditions.
func TestFailingScanNotRerunWithinPoll(t *testing.T) {
	t.Parallel()
	dyn, _ := newFakeDynamic(t, newClusterScan("flaky", map[string]any{
		"interval": "1h", "contexts": []any{"a"},
	}))
	runner := &fakeRunner{err: errors.New("no clusters reachable")}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop(), PollInterval: 10 * time.Millisecond})
	startController(t, c)

	waitForCalls(t, runner, 1)
	time.Sleep(300 * time.Millisecond)
	if n := runner.callCount(); n != 1 {
		t.Fatalf("failing scan ran %d times across 30 poll ticks, want 1", n)
	}

	status := readStatus(getClusterScan(t, dyn, "flaky"))
	if status.Phase != PhaseFailed || status.ConsecutiveFailures != 1 {
		t.Errorf("phase %q failures %d, want Failed and 1", status.Phase, status.ConsecutiveFailures)
	}
	if status.NextScanTime == nil || time.Until(*status.NextScanTime) < 50*time.Second {
		t.Errorf("next scan %v, want about one minute out", status.NextScanTime)
	}
	if !meta.IsStatusConditionTrue(status.Conditions, ConditionFailed) ||
		!meta.IsStatusConditionFalse(status.Conditions, ConditionReady) {
		t.Errorf("want Failed=True and Ready=False, got %+v", status.Conditions)
	}
}

// TestStatusPatchWritesZeros verifies counts that drop to zero are written, not left at their
// previous values.
func TestStatusPatchWritesZeros(t *testing.T) {
	t.Parallel()
	obj := newClusterScan("clean", map[string]any{"interval": "15m", "contexts": []any{"a"}})
	obj.Object["status"] = map[string]any{
		"phase": PhaseSucceeded, "lastScanTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"observedCritical": int64(5), "observedWarning": int64(3), "observedScore": int64(40),
		"consecutiveFailures": int64(2),
	}
	dyn, _ := newFakeDynamic(t, obj)
	runner := &fakeRunner{summary: ScanSummary{ScanID: "s2", Score: 100, Grade: "A", Clusters: 2}}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})
	reconcileOne(t, c, dyn, "clean")

	got := getClusterScan(t, dyn, "clean")
	for _, field := range []string{"observedCritical", "observedWarning", "consecutiveFailures"} {
		v, found, err := unstructured.NestedFieldNoCopy(got.Object, "status", field)
		if err != nil || !found {
			t.Errorf("status.%s missing after patch (found=%v err=%v)", field, found, err)
			continue
		}
		if fmt.Sprint(v) != "0" {
			t.Errorf("status.%s = %v, want 0", field, v)
		}
	}
}

// TestReconcileConditionsAndEvents verifies the conditions and Events a successful and a failed
// scan produce.
func TestReconcileConditionsAndEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Err            error
		WantReady      metav1.ConditionStatus
		WantFailed     metav1.ConditionStatus
		WantReason     string
		WantEvents     []string
		WantReconError bool
	}{{ // Test 0: A successful scan sets Ready and emits start and success Events.
		WantReady: metav1.ConditionTrue, WantFailed: metav1.ConditionFalse, WantReason: ReasonScanSucceeded,
		WantEvents: []string{
			"Normal ScanStarted Scan started",
			"Normal ScanSucceeded scan s1 completed: score 88 (B), 1 critical, 4 warning across 2 clusters",
		},
	}, { // Test 1: A failed scan sets Failed, emits a Warning, and returns an error for backoff.
		Err: errors.New("boom"), WantReady: metav1.ConditionFalse, WantFailed: metav1.ConditionTrue,
		WantReason: ReasonScanFailed, WantReconError: true,
		WantEvents: []string{"Normal ScanStarted Scan started", "Warning ScanFailed scan failed: boom"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			obj := newClusterScan("cs", map[string]any{"interval": "15m", "contexts": []any{"a"}})
			obj.SetGeneration(3)
			dyn, _ := newFakeDynamic(t, obj)
			rec := record.NewFakeRecorder(10)
			runner := &fakeRunner{err: test.Err, summary: ScanSummary{
				ScanID: "s1", Score: 88, Grade: "B", Critical: 1, Warning: 4, Clusters: 2,
			}}
			c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop(), Recorder: rec})
			_, err := c.reconcile(context.Background(), getClusterScan(t, dyn, "cs"))
			if (err != nil) != test.WantReconError {
				t.Errorf("reconcile err = %v, want error %v", err, test.WantReconError)
			}

			status := readStatus(getClusterScan(t, dyn, "cs"))
			if status.ObservedGeneration != 3 {
				t.Errorf("observedGeneration = %d, want 3", status.ObservedGeneration)
			}
			for _, want := range []struct {
				Type   string
				Status metav1.ConditionStatus
			}{{ConditionReady, test.WantReady}, {ConditionFailed, test.WantFailed}, {ConditionScanning, metav1.ConditionFalse}} {
				cond := meta.FindStatusCondition(status.Conditions, want.Type)
				if cond == nil {
					t.Errorf("condition %s missing", want.Type)
					continue
				}
				if cond.Status != want.Status || cond.Reason != test.WantReason || cond.ObservedGeneration != 3 {
					t.Errorf("condition %s = %s/%s gen %d, want %s/%s gen 3",
						want.Type, cond.Status, cond.Reason, cond.ObservedGeneration, want.Status, test.WantReason)
				}
			}
			if diff := cmp.Diff(test.WantEvents, drainEvents(rec)); diff != "" {
				t.Errorf("events mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestInvalidSpecEventOnce verifies an invalid interval emits one InvalidSpec event and is not
// re-patched or re-announced while the spec stays the same.
func TestInvalidSpecEventOnce(t *testing.T) {
	t.Parallel()
	dyn, _ := newFakeDynamic(t, newClusterScan("bad", map[string]any{
		"interval": "potato", "contexts": []any{"a"},
	}))
	rec := record.NewFakeRecorder(10)
	c := New(Config{Dynamic: dyn, Runner: &fakeRunner{}, Log: zap.NewNop(), Recorder: rec})
	reconcileOne(t, c, dyn, "bad")
	reconcileOne(t, c, dyn, "bad")

	events := drainEvents(rec)
	if len(events) != 1 {
		t.Fatalf("want one InvalidSpec event, got %v", events)
	}
	status := readStatus(getClusterScan(t, dyn, "bad"))
	if !meta.IsStatusConditionTrue(status.Conditions, ConditionFailed) {
		t.Errorf("want Failed=True, got %+v", status.Conditions)
	}
	if cond := meta.FindStatusCondition(status.Conditions, ConditionFailed); cond == nil || cond.Reason != ReasonInvalidSpec {
		t.Errorf("want reason InvalidSpec, got %+v", cond)
	}
}

// TestDeleteCancelsInflightScan verifies deleting a ClusterScan cancels the scan it is running.
func TestDeleteCancelsInflightScan(t *testing.T) {
	t.Parallel()
	dyn, gvr := newFakeDynamic(t, newClusterScan("doomed", map[string]any{
		"interval": "15m", "contexts": []any{"a"},
	}))
	runner := &fakeRunner{block: true}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop(), PollInterval: time.Hour})
	startController(t, c)

	waitForCalls(t, runner, 1)
	if err := dyn.Resource(gvr).Namespace("default").Delete(context.Background(), "doomed", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runner.observedCause() == nil {
		if time.Now().After(deadline) {
			t.Fatal("deleting the ClusterScan did not cancel its scan")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cause := runner.observedCause(); !errors.Is(cause, errClusterScanDeleted) {
		t.Errorf("cancel cause = %v, want errClusterScanDeleted", cause)
	}
}

// TestProcessNextBackoff verifies a failed reconcile is requeued through the rate limiter and a
// successful one resets its backoff.
func TestProcessNextBackoff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Err          error
		WantRequeues int
	}{{ // Test 0: A failed scan counts one rate-limited requeue.
		Err: errors.New("boom"), WantRequeues: 1,
	}, { // Test 1: A successful scan forgets the earlier backoff.
		WantRequeues: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			obj := newClusterScan("cs", map[string]any{"interval": "15m", "contexts": []any{"a"}})
			dyn, _ := newFakeDynamic(t, obj)
			c := New(Config{Dynamic: dyn, Runner: &fakeRunner{err: test.Err}, Log: zap.NewNop()})
			store := cache.NewStore(cache.MetaNamespaceKeyFunc)
			if err := store.Add(obj); err != nil {
				t.Fatalf("store add: %v", err)
			}
			queue := workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0))
			defer queue.ShutDown()
			if test.Err == nil {
				queue.AddRateLimited("default/cs")
			} else {
				queue.Add("default/cs")
			}
			c.processNext(context.Background(), queue, store)
			if got := queue.NumRequeues("default/cs"); got != test.WantRequeues {
				t.Errorf("requeues = %d, want %d", got, test.WantRequeues)
			}
		})
	}
}

// TestRetryDelay verifies the failure backoff doubles from one minute and caps at the interval.
func TestRetryDelay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Failures  int
		Interval  time.Duration
		WantDelay time.Duration
	}{
		{Failures: 1, Interval: time.Hour, WantDelay: time.Minute},             // Test 0: First failure waits the base.
		{Failures: 2, Interval: time.Hour, WantDelay: 2 * time.Minute},         // Test 1: Second doubles.
		{Failures: 3, Interval: time.Hour, WantDelay: 4 * time.Minute},         // Test 2: Third doubles again.
		{Failures: 6, Interval: 15 * time.Minute, WantDelay: 15 * time.Minute}, // Test 3: 32m caps at 15m.
		{Failures: 1, Interval: 30 * time.Second, WantDelay: 30 * time.Second}, // Test 4: Interval below the base wins.
		{Failures: 1000, Interval: time.Hour, WantDelay: time.Hour},            // Test 5: No overflow on a long streak.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := retryDelay(test.Failures, test.Interval); got != test.WantDelay {
				t.Errorf("retryDelay(%d, %s) = %s, want %s", test.Failures, test.Interval, got, test.WantDelay)
			}
		})
	}
}

// TestDueTime verifies how the next scan time is chosen from status and from memory.
func TestDueTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	tests := []struct {
		Status     ClusterScanStatus
		Memory     *scheduled
		Interval   time.Duration
		WantDue    time.Time
		WantBehind bool
	}{{ // Test 0: A never-scanned resource is due now.
		Interval: time.Hour, WantDue: now,
	}, { // Test 1: NextScanTime governs after a failure even though the last success is old.
		Status:   ClusterScanStatus{LastScanTime: at(-3 * time.Hour), NextScanTime: at(time.Minute), ConsecutiveFailures: 1},
		Interval: time.Hour, WantDue: now.Add(time.Minute),
	}, { // Test 2: A shortened interval after a success takes effect at once.
		Status:   ClusterScanStatus{LastScanTime: at(-20 * time.Minute), NextScanTime: at(40 * time.Minute)},
		Interval: 15 * time.Minute, WantDue: now.Add(-5 * time.Minute),
	}, { // Test 3: Without NextScanTime the last scan plus the interval is used.
		Status: ClusterScanStatus{LastScanTime: at(-10 * time.Minute)}, Interval: time.Hour,
		WantDue: now.Add(50 * time.Minute),
	}, { // Test 4: A later time in memory beats a stale cached status.
		Status: ClusterScanStatus{NextScanTime: at(-time.Minute)}, Memory: &scheduled{generation: 1, at: now.Add(time.Hour)},
		Interval: time.Hour, WantDue: now.Add(time.Hour), WantBehind: true,
	}, { // Test 5: Memory from another generation is ignored.
		Status: ClusterScanStatus{NextScanTime: at(-time.Minute)}, Memory: &scheduled{generation: 0, at: now.Add(time.Hour)},
		Interval: time.Hour, WantDue: now.Add(-time.Minute),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			dyn, _ := newFakeDynamic(t)
			c := New(Config{Dynamic: dyn, Runner: &fakeRunner{}, Log: zap.NewNop()})
			if test.Memory != nil {
				c.remember("ns/cs", test.Memory.generation, test.Memory.at)
			}
			got, behind := c.dueTime("ns/cs", 1, test.Status, test.Interval, now)
			if !got.Equal(test.WantDue) {
				t.Errorf("due = %s, want %s", got, test.WantDue)
			}
			if behind != test.WantBehind {
				t.Errorf("cacheBehind = %v, want %v", behind, test.WantBehind)
			}
		})
	}
}

// TestStatusToMapNamesEveryField verifies the patch body sets every managed field, writing
// zero counts as zero and empty values as null.
func TestStatusToMapNamesEveryField(t *testing.T) {
	t.Parallel()
	b, err := buildStatusPatch("", ClusterScanStatus{Phase: PhaseRunning})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := `{"status":{"conditions":[],"consecutiveFailures":0,"lastScanID":null,"lastScanTime":null,` +
		`"message":null,"nextScanTime":null,"observedClusters":0,"observedCritical":0,"observedGeneration":0,` +
		`"observedGrade":null,"observedScore":0,"observedWarning":0,"phase":"Running"}}`
	if diff := cmp.Diff(want, string(b)); diff != "" {
		t.Errorf("patch mismatch (-want +got):\n%s", diff)
	}
	var round map[string]any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("patch is not JSON: %v", err)
	}
}

// TestStaleCacheDoesNotClobberStatus verifies a reconcile handed a cached copy older than the
// controller's last write neither re-runs the scan nor writes status from the stale copy.
func TestStaleCacheDoesNotClobberStatus(t *testing.T) {
	t.Parallel()
	dyn, _ := newFakeDynamic(t, newClusterScan("cs", map[string]any{
		"interval": "1h", "contexts": []any{"a"},
	}))
	runner := &fakeRunner{err: errors.New("boom")}
	c := New(Config{Dynamic: dyn, Runner: runner, Log: zap.NewNop()})
	stale := getClusterScan(t, dyn, "cs")
	if _, err := c.reconcile(context.Background(), stale.DeepCopy()); err == nil {
		t.Fatal("want the failed scan reported as an error")
	}
	if _, err := c.reconcile(context.Background(), stale.DeepCopy()); err != nil {
		t.Fatalf("stale reconcile: %v", err)
	}
	if n := runner.callCount(); n != 1 {
		t.Errorf("scans = %d, want 1", n)
	}
	status := readStatus(getClusterScan(t, dyn, "cs"))
	if status.Phase != PhaseFailed || status.ConsecutiveFailures != 1 {
		t.Errorf("phase %q failures %d after a stale reconcile, want Failed and 1", status.Phase, status.ConsecutiveFailures)
	}
}

// TestStatusPatchCarriesResourceVersion verifies the patch is guarded by the object's
// resourceVersion so the API server rejects a write computed from a stale copy.
func TestStatusPatchCarriesResourceVersion(t *testing.T) {
	t.Parallel()
	b, err := buildStatusPatch("42", ClusterScanStatus{Phase: PhaseRunning})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Metadata.ResourceVersion != "42" {
		t.Errorf("resourceVersion = %q, want 42", body.Metadata.ResourceVersion)
	}
}

// enforceResourceVersion makes the fake client's status patches behave like the API server's:
// a patch naming a resourceVersion other than the stored one fails with a Conflict, and each
// accepted patch bumps the stored version.
func enforceResourceVersion(t *testing.T, dyn *dynamicfake.FakeDynamicClient) {
	t.Helper()
	var mu sync.Mutex
	react := k8stesting.ObjectReaction(dyn.Tracker())
	dyn.PrependReactor("patch", "clusterscans", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		pa := a.(k8stesting.PatchAction)
		current, err := dyn.Tracker().Get(ClusterScanGVR, pa.GetNamespace(), pa.GetName())
		if err != nil {
			return true, nil, err
		}
		stored := current.(*unstructured.Unstructured).GetResourceVersion()
		var body struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(pa.GetPatch(), &body); err != nil {
			return true, nil, err
		}
		if body.Metadata.ResourceVersion != "" && body.Metadata.ResourceVersion != stored {
			return true, nil, apierrors.NewConflict(ClusterScanGVR.GroupResource(), pa.GetName(),
				fmt.Errorf("resourceVersion %s is stale, stored is %s", body.Metadata.ResourceVersion, stored))
		}
		_, obj, err := react(a)
		if err != nil {
			return true, nil, err
		}
		u := obj.(*unstructured.Unstructured)
		n, _ := strconv.Atoi(stored)
		u.SetResourceVersion(strconv.Itoa(n + 1))
		if err := dyn.Tracker().Update(ClusterScanGVR, u, pa.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, u, nil
	})
}

// TestStatusPatchOptimisticLock verifies one reconcile's successive status writes each carry
// the version the previous write returned, and that a write from a stale copy is rejected
// rather than overwriting newer status.
func TestStatusPatchOptimisticLock(t *testing.T) {
	t.Parallel()
	obj := newClusterScan("cs", map[string]any{"interval": "15m", "contexts": []any{"a"}})
	obj.SetResourceVersion("1")
	dyn, _ := newFakeDynamic(t, obj)
	fake := dyn.(*dynamicfake.FakeDynamicClient)
	enforceResourceVersion(t, fake)
	c := New(Config{Dynamic: dyn, Runner: &fakeRunner{summary: ScanSummary{ScanID: "s1", Grade: "A"}}, Log: zap.NewNop()})

	stale := getClusterScan(t, dyn, "cs")
	if _, err := c.reconcile(context.Background(), stale.DeepCopy()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := getClusterScan(t, dyn, "cs")
	if rv := got.GetResourceVersion(); rv != "3" {
		t.Errorf("resourceVersion = %s, want 3 after the Running and Succeeded writes", rv)
	}
	if phase := readStatus(got).Phase; phase != PhaseSucceeded {
		t.Errorf("phase = %s, want Succeeded", phase)
	}

	err := c.patchStatus(context.Background(), stale, ClusterScanStatus{Phase: PhasePending})
	if !apierrors.IsConflict(err) {
		t.Errorf("stale write: want Conflict, got %v", err)
	}
	if phase := readStatus(getClusterScan(t, dyn, "cs")).Phase; phase != PhaseSucceeded {
		t.Errorf("phase after the rejected stale write = %s, want Succeeded", phase)
	}
}
