package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// mergePatchType is the patch strategy used for status updates. The status
// subresource accepts a partial JSON object and merges it into the existing
// status, which matches the controller's incremental update pattern.
const mergePatchType = types.MergePatchType

// informerResync is the shared informer's full-resync period. Watch events
// carry spec changes immediately; the resync is a safety net against missed
// events.
const informerResync = 10 * time.Minute

// reconcileWorkers is the number of goroutines draining the workqueue. The
// queue serializes work per key, so one slow scan never blocks reconciliation
// of other ClusterScans.
const reconcileWorkers = 4

// ScanRunner is the abstraction the controller uses to actually execute a
// scan. The server's Server type satisfies this interface; tests can substitute
// a fake to assert reconciliation behavior without spinning up scanners.
type ScanRunner interface {
	// ScanOnce executes one scan with the given options and returns the summary.
	// Implementations must be safe to call concurrently from multiple goroutines.
	ScanOnce(ctx context.Context, opts ScanOptions) (ScanSummary, error)
}

// ScanOptions describes one declarative scan invocation.
type ScanOptions struct {
	// Contexts is the kubeconfig context names to scan.
	Contexts []string
	// Group, when non-empty, supersedes Contexts: members of that group are scanned.
	Group string
	// Scanners restricts the scan to the named scanners. Empty runs all.
	Scanners []string
	// Emit selects which sinks receive outputs.
	Emit EmitOptions
	// ResourceName is the name of the originating ClusterScan, used for logging.
	ResourceName string
}

// ScanSummary holds the fields the controller writes back to status after a
// scan completes. Implementations should populate all fields; zero values are
// rendered as zeros in the CR status.
type ScanSummary struct {
	// ScanID is the persistent scan record identifier.
	ScanID string
	// Score is the fleet score (0-100).
	Score int
	// Grade is the letter grade (A-F).
	Grade string
	// Critical is the count of critical findings.
	Critical int
	// Warning is the count of warning findings.
	Warning int
	// Clusters is the number of clusters that produced data.
	Clusters int
}

// Config configures a Controller.
type Config struct {
	// Dynamic is the in-cluster dynamic client used to watch ClusterScans.
	Dynamic dynamic.Interface
	// Namespace, when non-empty, restricts the controller to one namespace.
	// Empty watches all namespaces (requires cluster-wide RBAC).
	Namespace string
	// Runner executes scans on the controller's behalf.
	Runner ScanRunner
	// Log is the structured logger.
	Log *zap.Logger
	// PollInterval is how often cached ClusterScans are re-enqueued to check
	// for due scans. Defaults to 15s when zero.
	PollInterval time.Duration
	// Recorder receives the Kubernetes Events the controller emits. When nil, Run builds one
	// on Events, and when both are nil Events are dropped.
	Recorder record.EventRecorder
	// Events is the core client Run uses to build an event recorder when Recorder is nil.
	Events typedcorev1.EventsGetter
}

// Controller reconciles ClusterScan resources. One Controller per process.
type Controller struct {
	// dyn reads ClusterScans and patches their status.
	dyn dynamic.Interface
	// namespace restricts the watch to one namespace when non-empty.
	namespace string
	// runner executes scans.
	runner ScanRunner
	// log is the structured logger.
	log *zap.Logger
	// poll is the re-enqueue interval.
	poll time.Duration
	// recorder emits Kubernetes Events. When nil, Run builds one on events.
	recorder record.EventRecorder
	// events builds the recorder in Run when recorder is nil.
	events typedcorev1.EventsGetter
	// mu guards inflight and next.
	mu sync.Mutex
	// inflight holds the cancel function of each ClusterScan's running scan, by key.
	inflight map[string]context.CancelCauseFunc
	// next remembers the next scan time this controller last wrote for each key, so a requeue
	// that reads a status the informer cache has not caught up on cannot re-run a scan.
	next map[string]scheduled
}

// scheduled is a next scan time and the resource generation it was computed for.
type scheduled struct {
	// generation is the ClusterScan generation the time was computed under.
	generation int64
	// at is the next scan time.
	at time.Time
}

// errClusterScanDeleted is the cancel cause of a scan whose ClusterScan was deleted.
var errClusterScanDeleted = errors.New("clusterscan deleted")

// failureRetryBase is the delay before retrying a failed scan. It doubles with each
// consecutive failure and never exceeds the resource's interval.
const failureRetryBase = time.Minute

// Condition types and reasons written to ClusterScan status.
const (
	// ConditionReady is True when the most recent scan succeeded.
	ConditionReady = "Ready"
	// ConditionScanning is True while a scan runs.
	ConditionScanning = "Scanning"
	// ConditionFailed is True when the most recent scan or the spec failed.
	ConditionFailed = "Failed"
	// ReasonScanStarted marks a scan in progress.
	ReasonScanStarted = "ScanStarted"
	// ReasonScanSucceeded marks a completed scan.
	ReasonScanSucceeded = "ScanSucceeded"
	// ReasonScanFailed marks a scan that returned an error.
	ReasonScanFailed = "ScanFailed"
	// ReasonInvalidSpec marks a spec the controller cannot act on.
	ReasonInvalidSpec = "InvalidSpec"
	// ReasonPaused marks a resource with spec.paused set.
	ReasonPaused = "Paused"
)

// New returns a Controller. Panics when required fields are nil to surface
// configuration mistakes before the operator quietly does nothing.
func New(cfg Config) *Controller {
	if cfg.Dynamic == nil {
		panic("controller: Dynamic required")
	}
	if cfg.Runner == nil {
		panic("controller: Runner required")
	}
	if cfg.Log == nil {
		panic("controller: Log required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 15 * time.Second
	}
	if cfg.Recorder == nil && cfg.Events == nil {
		cfg.Recorder = &record.FakeRecorder{}
	}
	return &Controller{
		dyn:       cfg.Dynamic,
		namespace: cfg.Namespace,
		runner:    cfg.Runner,
		log:       cfg.Log,
		poll:      cfg.PollInterval,
		recorder:  cfg.Recorder,
		events:    cfg.Events,
		inflight:  map[string]context.CancelCauseFunc{},
		next:      map[string]scheduled{},
	}
}

// Run reconciles ClusterScan resources until ctx is canceled. A shared
// informer watches for spec changes so new or edited resources reconcile
// immediately, and deletions cancel the resource's running scan. A ticker
// re-enqueues cached resources as a safety net; each reconcile also schedules
// its own key for the moment its next scan is due. Returns nil on a clean
// shutdown.
func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("controller starting",
		zap.String("namespace", c.namespace),
		zap.Duration("poll", c.poll),
	)

	if c.recorder == nil {
		broadcaster := record.NewBroadcaster(record.WithContext(ctx))
		broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: c.events.Events("")})
		defer broadcaster.Shutdown()
		c.recorder = broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: eventComponent})
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.dyn, informerResync, c.namespace, nil)
	informer := factory.ForResource(ClusterScanGVR).Informer()
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { enqueue(queue, obj) },
		UpdateFunc: func(_, obj any) { enqueue(queue, obj) },
		DeleteFunc: c.forget,
	})
	if err != nil {
		return fmt.Errorf("controller: register event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return errors.New("controller: informer cache sync failed")
	}

	go c.requeueLoop(ctx, informer.GetStore(), queue)

	done := make(chan struct{}, reconcileWorkers)
	for range reconcileWorkers {
		go func() {
			defer func() { done <- struct{}{} }()
			for c.processNext(ctx, queue, informer.GetStore()) {
			}
		}()
	}

	<-ctx.Done()
	queue.ShutDown()
	for range reconcileWorkers {
		<-done
	}
	factory.Shutdown()
	c.log.Info("controller stopped")
	return nil
}

// eventComponent is the source component on Events the controller emits.
const eventComponent = "fleetsweeper-controller"

// forget handles a ClusterScan deletion: it cancels the resource's running scan, if any, and
// drops its remembered schedule.
func (c *Controller) forget(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	c.mu.Lock()
	cancel := c.inflight[key]
	delete(c.next, key)
	c.mu.Unlock()
	if cancel != nil {
		c.log.Info("controller: clusterscan deleted; canceling its scan", zap.String("key", key))
		cancel(errClusterScanDeleted)
	}
}

// requeueLoop re-enqueues every cached ClusterScan on the poll interval so
// interval-due scans fire even when nothing changes on the API server.
func (c *Controller) requeueLoop(ctx context.Context, store cache.Store, queue workqueue.TypedRateLimitingInterface[string]) {
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, obj := range store.List() {
				enqueue(queue, obj)
			}
		}
	}
}

// processNext reconciles one queue item. The workqueue guarantees a key is
// never handed to two workers at once, so per-resource work is serialized. A
// failed reconcile is requeued with the queue's backoff, and the backoff is
// reset only on success. Returns false when the queue has shut down.
func (c *Controller) processNext(ctx context.Context, queue workqueue.TypedRateLimitingInterface[string], store cache.Store) bool {
	key, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(key)

	obj, exists, err := store.GetByKey(key)
	if err != nil || !exists {
		queue.Forget(key)
		return true
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		queue.Forget(key)
		return true
	}
	wait, err := c.reconcile(ctx, u.DeepCopy())
	if err != nil {
		if ctx.Err() == nil {
			c.log.Warn("controller: reconcile failed; requeueing with backoff",
				zap.String("key", key), zap.Error(err))
			queue.AddRateLimited(key)
		}
		return true
	}
	queue.Forget(key)
	if wait > 0 {
		queue.AddAfter(key, wait)
	}
	return true
}

// enqueue adds the object's namespace/name key to the queue. Objects without
// a derivable key are ignored.
func enqueue(queue workqueue.TypedRateLimitingInterface[string], obj any) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	queue.Add(key)
}

// reconcile processes a single ClusterScan resource: decides whether a scan is due, fires it,
// and writes status, Conditions, and Events. It returns how long until the resource is next
// due, or an error when the scan or a status write failed and the key should back off.
func (c *Controller) reconcile(ctx context.Context, obj *unstructured.Unstructured) (time.Duration, error) {
	recordReconcile()

	name := obj.GetName()
	ns := obj.GetNamespace()
	key := ns + "/" + name
	gen := obj.GetGeneration()
	status := readStatus(obj)
	status.ObservedGeneration = gen

	spec, err := readSpec(obj)
	if err == nil && spec.Interval == "" {
		err = errors.New("spec.interval is required")
	}
	var interval time.Duration
	if err == nil {
		interval, err = time.ParseDuration(spec.Interval)
		if err == nil && interval <= 0 {
			err = errors.New("spec.interval must be positive")
		}
		if err != nil {
			err = fmt.Errorf("invalid spec.interval %q (use a Go duration like 15m): %w", spec.Interval, err)
		}
	}
	if err != nil {
		recordReconcileFail()
		c.log.Warn("controller: invalid spec",
			zap.String("name", name), zap.String("namespace", ns), zap.Error(err))
		msg := "invalid spec: " + err.Error()
		if status.Phase == PhaseFailed && status.Message == msg {
			return 0, nil
		}
		status.Phase = PhaseFailed
		status.Message = msg
		setConditions(&status, gen, metav1.ConditionFalse, metav1.ConditionFalse, metav1.ConditionTrue,
			ReasonInvalidSpec, msg)
		c.recorder.Event(obj, corev1.EventTypeWarning, ReasonInvalidSpec, msg)
		return 0, c.patchStatus(ctx, obj, status)
	}

	if spec.Paused {
		recordPaused()
		recordReconcileOK()
		if status.Phase == PhasePaused {
			return 0, nil
		}
		status.Phase = PhasePaused
		status.Message = "paused by spec.paused"
		setConditions(&status, gen, metav1.ConditionFalse, metav1.ConditionFalse, metav1.ConditionFalse,
			ReasonPaused, status.Message)
		return 0, c.patchStatus(ctx, obj, status)
	}

	now := time.Now().UTC()
	due, cacheBehind := c.dueTime(key, gen, status, interval, now)
	if now.Before(due) {
		recordReconcileOK()
		if !cacheBehind && (status.NextScanTime == nil || !status.NextScanTime.Equal(due)) {
			status.NextScanTime = &due
			if status.Phase == "" {
				status.Phase = PhasePending
			}
			if err := c.patchStatus(ctx, obj, status); err != nil {
				return 0, err
			}
		}
		return due.Sub(now), nil
	}

	status.Phase = PhaseRunning
	status.Message = "scan triggered by controller"
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: ConditionScanning, Status: metav1.ConditionTrue, ObservedGeneration: gen,
		Reason: ReasonScanStarted, Message: status.Message,
	})
	if err := c.patchStatus(ctx, obj, status); err != nil {
		return 0, err
	}
	c.recorder.Event(obj, corev1.EventTypeNormal, ReasonScanStarted, "Scan started")

	scanCtx, cancel := context.WithCancelCause(ctx)
	c.mu.Lock()
	c.inflight[key] = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.inflight, key)
		c.mu.Unlock()
		cancel(nil)
	}()

	recordScanTriggered()
	summary, scanErr := c.runner.ScanOnce(scanCtx, ScanOptions{
		Contexts:     spec.Contexts,
		Group:        spec.Group,
		Scanners:     spec.Scanners,
		Emit:         spec.Emit,
		ResourceName: key,
	})
	if errors.Is(context.Cause(scanCtx), errClusterScanDeleted) {
		recordScanResult(false)
		c.log.Info("controller: scan canceled because its clusterscan was deleted", zap.String("key", key))
		return 0, nil
	}
	if ctx.Err() != nil {
		recordScanResult(false)
		return 0, ctx.Err()
	}

	completedAt := time.Now().UTC()
	if scanErr != nil {
		recordScanResult(false)
		recordReconcileFail()
		c.log.Warn("controller: scan failed",
			zap.String("name", name), zap.String("namespace", ns), zap.Error(scanErr))
		status.ConsecutiveFailures++
		next := completedAt.Add(retryDelay(status.ConsecutiveFailures, interval))
		c.remember(key, gen, next)
		status.Phase = PhaseFailed
		status.Message = "scan failed: " + scanErr.Error()
		status.NextScanTime = &next
		setConditions(&status, gen, metav1.ConditionFalse, metav1.ConditionFalse, metav1.ConditionTrue,
			ReasonScanFailed, status.Message)
		c.recorder.Event(obj, corev1.EventTypeWarning, ReasonScanFailed, status.Message)
		if err := c.patchStatus(ctx, obj, status); err != nil {
			return 0, errors.Join(fmt.Errorf("scan: %w", scanErr), err)
		}
		return 0, fmt.Errorf("scan: %w", scanErr)
	}

	recordScanResult(true)
	recordReconcileOK()
	next := completedAt.Add(interval)
	c.remember(key, gen, next)
	status.Phase = PhaseSucceeded
	status.Message = fmt.Sprintf("scan %s completed: score %d (%s), %d critical, %d warning across %d clusters",
		summary.ScanID, summary.Score, summary.Grade, summary.Critical, summary.Warning, summary.Clusters)
	status.LastScanID = summary.ScanID
	status.LastScanTime = &completedAt
	status.NextScanTime = &next
	status.ConsecutiveFailures = 0
	status.ObservedScore = summary.Score
	status.ObservedGrade = summary.Grade
	status.ObservedCritical = summary.Critical
	status.ObservedWarning = summary.Warning
	status.ObservedClusters = summary.Clusters
	setConditions(&status, gen, metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionFalse,
		ReasonScanSucceeded, status.Message)
	c.recorder.Event(obj, corev1.EventTypeNormal, ReasonScanSucceeded, status.Message)
	if err := c.patchStatus(ctx, obj, status); err != nil {
		return 0, err
	}
	return interval, nil
}

// dueTime returns when the resource's next scan is due. NextScanTime governs, so a failed scan
// waits out its retry delay. When the last scan succeeded, a shortened interval takes effect at
// once rather than after the old next scan. A time this controller wrote under the current
// generation wins when it is later, and cacheBehind then reports that the cached status
// predates that write, so the caller must not write status from it.
func (c *Controller) dueTime(key string, gen int64, status ClusterScanStatus, interval time.Duration,
	now time.Time) (due time.Time, cacheBehind bool) {
	due = now
	switch {
	case status.NextScanTime != nil:
		due = *status.NextScanTime
	case status.LastScanTime != nil:
		due = status.LastScanTime.Add(interval)
	}
	if status.LastScanTime != nil && status.ConsecutiveFailures == 0 {
		if byInterval := status.LastScanTime.Add(interval); byInterval.Before(due) {
			due = byInterval
		}
	}
	c.mu.Lock()
	mem, ok := c.next[key]
	c.mu.Unlock()
	if ok && mem.generation == gen && mem.at.After(due) {
		return mem.at, true
	}
	return due, false
}

// remember records the next scan time written for key under generation gen.
func (c *Controller) remember(key string, gen int64, at time.Time) {
	c.mu.Lock()
	c.next[key] = scheduled{generation: gen, at: at}
	c.mu.Unlock()
}

// retryDelay returns how long to wait after the given number of consecutive failures:
// failureRetryBase doubled for each failure after the first, capped at interval.
func retryDelay(failures int, interval time.Duration) time.Duration {
	delay := failureRetryBase
	for i := 1; i < failures && delay < interval; i++ {
		delay *= 2
	}
	return min(delay, interval)
}

// setConditions writes the Ready, Scanning, and Failed conditions with one reason and message.
func setConditions(status *ClusterScanStatus, gen int64, ready, scanning, failed metav1.ConditionStatus,
	reason, message string) {
	for _, cond := range []metav1.Condition{
		{Type: ConditionReady, Status: ready},
		{Type: ConditionScanning, Status: scanning},
		{Type: ConditionFailed, Status: failed},
	} {
		cond.ObservedGeneration = gen
		cond.Reason = reason
		cond.Message = message
		meta.SetStatusCondition(&status.Conditions, cond)
	}
}

// patchStatus writes every controller-managed status field through the status subresource,
// including zero values, so a count that drops to zero or a cleared field is recorded rather
// than left at its old value. The patch carries obj's resourceVersion, so a write computed
// from a stale cached copy fails with a Conflict and the key backs off and rereads instead of
// overwriting newer status. On success obj takes the new resourceVersion so the next patch in
// the same reconcile applies. A NotFound means the resource was deleted and is not an error.
func (c *Controller) patchStatus(ctx context.Context, obj *unstructured.Unstructured, status ClusterScanStatus) error {
	patch, err := buildStatusPatch(obj.GetResourceVersion(), status)
	if err != nil {
		return fmt.Errorf("build status patch: %w", err)
	}
	updated, err := c.dyn.Resource(ClusterScanGVR).
		Namespace(obj.GetNamespace()).
		Patch(ctx, obj.GetName(), mergePatchType, patch, metav1.PatchOptions{}, "status")
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("patch status %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	}
	obj.SetResourceVersion(updated.GetResourceVersion())
	return nil
}

// readSpec decodes the spec section into a typed ClusterScanSpec. Returns an
// error when the spec is malformed beyond what the CRD schema enforces.
func readSpec(obj *unstructured.Unstructured) (ClusterScanSpec, error) {
	raw, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil {
		return ClusterScanSpec{}, fmt.Errorf("spec: %w", err)
	}
	if !found {
		return ClusterScanSpec{}, errors.New("spec missing")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return ClusterScanSpec{}, fmt.Errorf("spec marshal: %w", err)
	}
	var out ClusterScanSpec
	if err := json.Unmarshal(b, &out); err != nil {
		return ClusterScanSpec{}, fmt.Errorf("spec unmarshal: %w", err)
	}
	return out, nil
}

// readStatus decodes the existing status section. Missing or malformed status
// is treated as an empty status so reconciliation can proceed from scratch.
func readStatus(obj *unstructured.Unstructured) ClusterScanStatus {
	raw, found, err := unstructured.NestedMap(obj.Object, "status")
	if err != nil || !found {
		return ClusterScanStatus{}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return ClusterScanStatus{}
	}
	var out ClusterScanStatus
	if err := json.Unmarshal(b, &out); err != nil {
		return ClusterScanStatus{}
	}
	return out
}

// buildStatusPatch serializes a JSON merge patch that sets every controller-managed status
// field, guarded by resourceVersion when one is known.
func buildStatusPatch(resourceVersion string, status ClusterScanStatus) ([]byte, error) {
	body := map[string]any{"status": statusToMap(status)}
	if resourceVersion != "" {
		body["metadata"] = map[string]any{"resourceVersion": resourceVersion}
	}
	return json.Marshal(body)
}

// statusToMap converts a ClusterScanStatus into a merge patch body that names every managed
// field. Counts are written even when zero. An empty string or nil time is written as null,
// which removes the field, because the schema rejects an empty grade and a cleared value must
// not survive from an earlier scan.
func statusToMap(s ClusterScanStatus) map[string]any {
	conditions := s.Conditions
	if conditions == nil {
		conditions = []metav1.Condition{}
	}
	return map[string]any{
		"phase":               nullIfEmpty(s.Phase),
		"lastScanID":          nullIfEmpty(s.LastScanID),
		"lastScanTime":        rfc3339OrNull(s.LastScanTime),
		"nextScanTime":        rfc3339OrNull(s.NextScanTime),
		"observedScore":       s.ObservedScore,
		"observedGrade":       nullIfEmpty(s.ObservedGrade),
		"observedCritical":    s.ObservedCritical,
		"observedWarning":     s.ObservedWarning,
		"observedClusters":    s.ObservedClusters,
		"observedGeneration":  s.ObservedGeneration,
		"consecutiveFailures": s.ConsecutiveFailures,
		"message":             nullIfEmpty(s.Message),
		"conditions":          conditions,
	}
}

// nullIfEmpty returns nil for an empty string so the merge patch removes the field.
func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// rfc3339OrNull formats t as RFC 3339, or returns nil so the merge patch removes the field.
func rfc3339OrNull(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
