package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// mergePatchType is the patch strategy used for status updates. The status
// subresource accepts a partial JSON object and merges it into the existing
// status, which matches the controller's incremental update pattern.
const mergePatchType = types.MergePatchType

// ScanRunner is the abstraction the controller uses to actually execute a
// scan. The server's Server type satisfies this interface; tests can substitute
// a fake to assert reconciliation behaviour without spinning up scanners.
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
	// PollInterval is how often the controller lists ClusterScans to check for
	// due scans. Defaults to 15s when zero.
	PollInterval time.Duration
}

// Controller reconciles ClusterScan resources. One Controller per process.
type Controller struct {
	dyn       dynamic.Interface
	namespace string
	runner    ScanRunner
	log       *zap.Logger
	poll      time.Duration

	// inFlight tracks resources with a scan currently executing so the next
	// reconciliation pass does not double-fire on a slow scan.
	mu       sync.Mutex
	inFlight map[string]struct{}
}

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
	return &Controller{
		dyn:       cfg.Dynamic,
		namespace: cfg.Namespace,
		runner:    cfg.Runner,
		log:       cfg.Log,
		poll:      cfg.PollInterval,
		inFlight:  make(map[string]struct{}),
	}
}

// Run reconciles ClusterScan resources until ctx is cancelled. It returns nil
// on a clean shutdown and a wrapped error on the first unrecoverable failure.
func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("controller starting",
		zap.String("namespace", c.namespace),
		zap.Duration("poll", c.poll),
	)
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()

	c.reconcileAll(ctx)
	for {
		select {
		case <-ctx.Done():
			c.log.Info("controller stopped")
			return nil
		case <-ticker.C:
			c.reconcileAll(ctx)
		}
	}
}

// reconcileAll lists every ClusterScan in the configured namespace scope and
// reconciles each. Errors are logged so a transient API server hiccup does not
// kill the controller loop.
func (c *Controller) reconcileAll(ctx context.Context) {
	list, err := c.list(ctx)
	if err != nil {
		c.log.Warn("controller: list failed", zap.Error(err))
		return
	}
	for i := range list.Items {
		item := &list.Items[i]
		c.reconcile(ctx, item)
	}
}

// list returns every ClusterScan visible in the configured namespace.
func (c *Controller) list(ctx context.Context) (*unstructured.UnstructuredList, error) {
	if c.namespace == "" {
		return c.dyn.Resource(ClusterScanGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}
	return c.dyn.Resource(ClusterScanGVR).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
}

// reconcile processes a single ClusterScan resource: decides whether a scan
// is due, fires it, and updates status.
func (c *Controller) reconcile(ctx context.Context, obj *unstructured.Unstructured) {
	recordReconcile()

	name := obj.GetName()
	ns := obj.GetNamespace()
	key := ns + "/" + name

	spec, err := readSpec(obj)
	if err != nil {
		recordReconcileFail()
		c.log.Warn("controller: invalid spec",
			zap.String("name", name), zap.String("namespace", ns), zap.Error(err))
		c.patchStatus(ctx, obj, ClusterScanStatus{
			Phase:   PhaseFailed,
			Message: "invalid spec: " + err.Error(),
		})
		return
	}

	status := readStatus(obj)

	if spec.Paused {
		recordPaused()
		recordReconcileOK()
		if status.Phase != PhasePaused {
			status.Phase = PhasePaused
			status.Message = "paused by spec.paused"
			c.patchStatus(ctx, obj, status)
		}
		return
	}

	interval, err := time.ParseDuration(spec.Interval)
	if err != nil || interval <= 0 {
		recordReconcileFail()
		c.patchStatus(ctx, obj, ClusterScanStatus{
			Phase:   PhaseFailed,
			Message: "invalid spec.interval (use a Go duration like 15m)",
		})
		return
	}

	now := time.Now().UTC()
	due := now
	if status.LastScanTime != nil {
		due = status.LastScanTime.Add(interval)
	}
	if now.Before(due) {
		recordReconcileOK()
		next := due
		if status.NextScanTime == nil || !status.NextScanTime.Equal(next) {
			status.NextScanTime = &next
			if status.Phase == "" {
				status.Phase = PhasePending
			}
			c.patchStatus(ctx, obj, status)
		}
		return
	}

	if !c.tryClaim(key) {
		recordReconcileOK()
		return
	}
	defer c.release(key)

	running := ClusterScanStatus{
		Phase:        PhaseRunning,
		Message:      "scan triggered by controller",
		LastScanTime: status.LastScanTime,
		LastScanID:   status.LastScanID,
	}
	c.patchStatus(ctx, obj, running)

	recordScanTriggered()
	summary, scanErr := c.runner.ScanOnce(ctx, ScanOptions{
		Contexts:     spec.Contexts,
		Group:        spec.Group,
		Scanners:     spec.Scanners,
		Emit:         spec.Emit,
		ResourceName: key,
	})

	completedAt := time.Now().UTC()
	next := completedAt.Add(interval)
	if scanErr != nil {
		recordScanResult(false)
		recordReconcileFail()
		c.log.Warn("controller: scan failed",
			zap.String("name", name), zap.String("namespace", ns), zap.Error(scanErr))
		c.patchStatus(ctx, obj, ClusterScanStatus{
			Phase:        PhaseFailed,
			Message:      "scan failed: " + scanErr.Error(),
			NextScanTime: &next,
			LastScanID:   status.LastScanID,
			LastScanTime: status.LastScanTime,
		})
		return
	}

	recordScanResult(true)
	recordReconcileOK()
	c.patchStatus(ctx, obj, ClusterScanStatus{
		Phase:            PhaseSucceeded,
		Message:          fmt.Sprintf("scan %s completed", summary.ScanID),
		LastScanID:       summary.ScanID,
		LastScanTime:     &completedAt,
		NextScanTime:     &next,
		ObservedScore:    summary.Score,
		ObservedGrade:    summary.Grade,
		ObservedCritical: summary.Critical,
		ObservedWarning:  summary.Warning,
		ObservedClusters: summary.Clusters,
	})
}

// patchStatus merges the supplied status into the resource and writes it via
// the status subresource. Status patch failures are logged; reconciliation
// continues so the next pass can retry.
func (c *Controller) patchStatus(ctx context.Context, obj *unstructured.Unstructured, status ClusterScanStatus) {
	patch, err := buildStatusPatch(status)
	if err != nil {
		c.log.Warn("controller: build patch", zap.Error(err))
		return
	}
	_, err = c.dyn.Resource(ClusterScanGVR).
		Namespace(obj.GetNamespace()).
		Patch(ctx, obj.GetName(), mergePatchType, patch, metav1.PatchOptions{}, "status")
	if err != nil && !apierrors.IsNotFound(err) {
		c.log.Warn("controller: patch status",
			zap.String("name", obj.GetName()),
			zap.String("namespace", obj.GetNamespace()),
			zap.Error(err),
		)
	}
}

// tryClaim returns true when the caller acquired the inflight slot for key.
// Returns false when another goroutine is already running a scan for the
// same key, in which case the caller should skip this reconciliation pass.
func (c *Controller) tryClaim(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, busy := c.inFlight[key]; busy {
		return false
	}
	c.inFlight[key] = struct{}{}
	return true
}

// release frees the inflight slot for key.
func (c *Controller) release(key string) {
	c.mu.Lock()
	delete(c.inFlight, key)
	c.mu.Unlock()
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

// buildStatusPatch serialises a strategic-merge style patch body containing
// only the status fields the controller manages.
func buildStatusPatch(status ClusterScanStatus) ([]byte, error) {
	body := map[string]any{"status": statusToMap(status)}
	return json.Marshal(body)
}

// statusToMap converts a ClusterScanStatus into the map shape the API server
// expects in a strategic merge patch. Optional fields are omitted when empty
// so the patch is minimal.
func statusToMap(s ClusterScanStatus) map[string]any {
	m := map[string]any{}
	if s.Phase != "" {
		m["phase"] = s.Phase
	}
	if s.LastScanID != "" {
		m["lastScanID"] = s.LastScanID
	}
	if s.LastScanTime != nil {
		m["lastScanTime"] = s.LastScanTime.Format(time.RFC3339)
	}
	if s.NextScanTime != nil {
		m["nextScanTime"] = s.NextScanTime.Format(time.RFC3339)
	}
	if s.ObservedScore > 0 {
		m["observedScore"] = s.ObservedScore
	}
	if s.ObservedGrade != "" {
		m["observedGrade"] = s.ObservedGrade
	}
	if s.ObservedCritical > 0 {
		m["observedCritical"] = s.ObservedCritical
	}
	if s.ObservedWarning > 0 {
		m["observedWarning"] = s.ObservedWarning
	}
	if s.ObservedClusters > 0 {
		m["observedClusters"] = s.ObservedClusters
	}
	if s.Message != "" {
		m["message"] = s.Message
	}
	return m
}
