package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
	"github.com/dcadolph/fleetsweeper/internal/tracing"
)

// Scan sources name the caller of executeScan in logs and events.
const (
	// scanSourceScheduled is the --scan-interval scheduler.
	scanSourceScheduled = "scheduled"
	// scanSourceTriggered is POST /api/scans.
	scanSourceTriggered = "triggered"
	// scanSourceInbound is the HMAC-signed inbound webhook.
	scanSourceInbound = "inbound"
	// scanSourceController is the ClusterScan controller.
	scanSourceController = "controller"
)

// dispatchWorkers bounds how many scans may be delivering Slack and webhook notifications at
// once. A scan that finishes while every slot is busy waits for one, so a slow subscriber
// applies backpressure instead of piling up goroutines.
const dispatchWorkers = 4

// errNoClusters reports that no requested context produced a usable client.
var errNoClusters = errors.New("no clusters reachable")

// emitAll turns on every per-scan output. Every caller except the controller, whose
// ClusterScan chooses its own outputs, uses it.
var emitAll = controller.EmitOptions{FleetDriftReport: true, PolicyReport: true, Slack: true}

// scanRequest describes one scan for executeScan.
type scanRequest struct {
	// Source names the caller, one of the scanSource constants.
	Source string
	// ScanID is the ID to save the scan under. Empty generates one.
	ScanID string
	// Contexts lists the kubeconfig contexts to scan.
	Contexts []string
	// Scanners is the scanner set to run. Nil runs every registered scanner.
	Scanners map[string]scanner.Scanner
	// Emit selects the per-scan outputs. Outbound webhooks always fire when configured.
	Emit controller.EmitOptions
}

// executeScan is the single scan pipeline behind the scheduler, the trigger endpoint, the
// inbound webhook, and the controller. It holds scanMu while it connects, scans, saves, builds
// the report with cluster tags and groups, and writes local report files, then releases the
// lock before publishing the outcome event and handing Slack and webhook delivery to the
// bounded dispatcher. Every outcome is counted in the scan metrics.
func (s *Server) executeScan(ctx context.Context, req scanRequest) (string, *report.Report, error) {
	scanID := req.ScanID
	if scanID == "" {
		scanID = store.NewScanID()
	}
	scanners := req.Scanners
	if scanners == nil {
		scanners = s.registry.All()
	}
	log := s.log.With(zap.String("source", req.Source), zap.String("scan_id", scanID))

	started := time.Now()
	rpt, clusters, err := s.scanAndSave(ctx, log, scanID, req, scanners)
	if err != nil {
		s.scansErr.Add(1)
		s.recordScanCompletion(false)
		log.Warn("scan failed", zap.Error(err))
		s.PublishEvent(EventScanFailed, map[string]any{
			"scan_id": scanID,
			"source":  req.Source,
			"error":   safeMessage(err, "scan failed"),
		})
		return scanID, nil, err
	}
	s.scansOK.Add(1)
	s.recordScanDuration(time.Since(started))
	s.recordScanCompletion(true)
	log.Info("scan complete", zap.Int("clusters", clusters))
	s.PublishEvent(EventScanComplete, map[string]any{
		"scan_id":  scanID,
		"source":   req.Source,
		"clusters": clusters,
		"score":    rpt.FleetScore.Score,
		"grade":    rpt.FleetScore.Grade,
	})
	s.dispatchNotifications(rpt, req.Emit)
	return scanID, rpt, nil
}

// scanAndSave is the part of executeScan that runs under scanMu. It returns the built report
// and the number of clusters scanned.
func (s *Server) scanAndSave(ctx context.Context, log *zap.Logger, scanID string, req scanRequest,
	scanners map[string]scanner.Scanner) (*report.Report, int, error) {
	if len(req.Contexts) == 0 {
		return nil, 0, errors.New("no contexts to scan")
	}
	if len(scanners) == 0 {
		return nil, 0, errors.New("no scanners selected")
	}

	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("canceled while waiting for the scan lock: %w", err)
	}

	log.Info("scan starting", zap.Int("contexts", len(req.Contexts)))
	clients := kube.ConnectAll(ctx, s.kubeconfigPath, req.Contexts, s.workers)
	if len(clients) == 0 {
		return nil, 0, errNoClusters
	}
	results := RunScanners(ctx, clients, scanners, s.workers, scanner.DefaultScanTimeout, s.log)
	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	rec := store.ScanRecord{ID: scanID, Timestamp: time.Now().UTC(), Clusters: clusterNames}
	if _, err := s.store.SaveScanRecord(ctx, rec, results); err != nil {
		return nil, 0, fmt.Errorf("save scan: %w", err)
	}

	opts := s.reportOptions(ctx, log)
	opts.Timestamp = rec.Timestamp
	rpt := report.Build(clusterNames, results, opts)
	if req.Emit.FleetDriftReport {
		s.writeFleetDriftIfConfigured(rpt, scanID)
	}
	if req.Emit.PolicyReport {
		s.writePolicyReportIfConfigured(rpt, scanID)
	}
	return rpt, len(clusterNames), nil
}

// reportOptions loads the cluster tags and groups a freshly saved scan's report is built with.
// The scan is already saved, so a failed lookup is logged and that input left out rather than
// failing the scan.
func (s *Server) reportOptions(ctx context.Context, log *zap.Logger) report.BuildOptions {
	var opts report.BuildOptions
	tags, err := projectCohortTags(ctx, s, cohortTagKey)
	if err != nil {
		log.Warn("scan report: list cohort tags", zap.Error(err))
	}
	opts.ClusterTags = tags
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		log.Warn("scan report: list groups", zap.Error(err))
	}
	if len(groups) > 0 {
		opts.Groups = make(map[string][]string, len(groups))
		for _, g := range groups {
			opts.Groups[g.Name] = g.Clusters
		}
	}
	return opts
}

// dispatchNotifications delivers a report to Slack and outbound webhooks on a bounded worker
// pool, so a slow subscriber never holds scanMu or delays the next scan. It waits for a free
// slot before starting the delivery, and gives up when the server shuts down.
func (s *Server) dispatchNotifications(rpt *report.Report, emit controller.EmitOptions) {
	slack := emit.Slack && s.slackWebhookURL != ""
	if !slack && s.webhookDispatcher == nil {
		return
	}
	select {
	case s.dispatchSem <- struct{}{}:
	case <-s.ctx.Done():
		return
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer func() { <-s.dispatchSem }()
		if slack {
			s.notifySlackForReport(s.ctx, rpt)
		}
		s.dispatchWebhooksIfConfigured(s.ctx, rpt)
	}()
}

// ScanOnce executes a single scan with the given options and returns a summary.
// It satisfies the controller.ScanRunner interface so the ClusterScan operator
// can drive scans without depending on internal server types beyond Server.
// It runs through executeScan, so a controller-driven scan and any other scan
// cannot interleave.
func (s *Server) ScanOnce(ctx context.Context, opts controller.ScanOptions) (controller.ScanSummary, error) {
	contexts, err := s.resolveOptionContexts(ctx, opts)
	if err != nil {
		return controller.ScanSummary{}, err
	}
	scanners := s.selectScanners(opts.Scanners)
	if len(scanners) == 0 {
		return controller.ScanSummary{}, errors.New("scan once: no scanners selected")
	}
	s.log.Info("controller scan requested",
		zap.String("resource", opts.ResourceName),
		zap.Int("contexts", len(contexts)),
	)

	scanID, rpt, err := s.executeScan(ctx, scanRequest{
		Source:   scanSourceController,
		Contexts: contexts,
		Scanners: scanners,
		Emit:     opts.Emit,
	})
	if err != nil {
		return controller.ScanSummary{}, fmt.Errorf("scan once: %w", err)
	}
	return controller.ScanSummary{
		ScanID:   scanID,
		Score:    rpt.FleetScore.Score,
		Grade:    rpt.FleetScore.Grade,
		Critical: countFindings(rpt, report.SeverityCritical),
		Warning:  countFindings(rpt, report.SeverityWarning),
		Clusters: len(rpt.Clusters),
	}, nil
}

// resolveOptionContexts produces the final context list, expanding a group
// reference when set. A non-empty Group takes precedence over Contexts so
// ClusterScan authors can pick one mode unambiguously.
func (s *Server) resolveOptionContexts(ctx context.Context, opts controller.ScanOptions) ([]string, error) {
	if opts.Group != "" {
		g, err := s.store.GetGroup(ctx, opts.Group)
		if err != nil {
			return nil, fmt.Errorf("resolve group %q: %w", opts.Group, err)
		}
		return g.Clusters, nil
	}
	return opts.Contexts, nil
}

// selectScanners filters the registered scanners by the supplied allowlist.
// An empty or nil allowlist means "all registered scanners," matching the
// behavior of the CLI scan command and existing HTTP trigger.
func (s *Server) selectScanners(allow []string) map[string]scanner.Scanner {
	all := s.registry.All()
	if len(allow) == 0 {
		return all
	}
	out := make(map[string]scanner.Scanner, len(allow))
	for _, name := range allow {
		if sc, ok := all[name]; ok {
			out[name] = sc
		}
	}
	return out
}

// countFindings totals findings of the given severity in a built report.
func countFindings(rpt *report.Report, sev string) int {
	if rpt == nil {
		return 0
	}
	n := 0
	for _, f := range rpt.Findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// RunScanners executes every scanner against every client with at most workers running at
// once, each bounded by timeout, and returns results keyed by context then scanner. A scanner
// that fails, or that never starts because ctx was canceled, is recorded as an errored result
// so the report counts it as missing coverage rather than as a clean read. Each
// scanner-cluster pair gets a child span so traces show the per-scanner fan-out.
func RunScanners(ctx context.Context, clients []*kube.Client, scanners map[string]scanner.Scanner, workers int,
	timeout time.Duration, log *zap.Logger) map[string]map[string]scanner.Result {
	if workers <= 0 {
		workers = 1
	}
	ctx, rootSpan := tracing.Tracer().Start(ctx, "fleetsweeper.scan",
		trace.WithAttributes(
			attribute.Int("fleetsweeper.cluster_count", len(clients)),
			attribute.Int("fleetsweeper.scanner_count", len(scanners)),
		),
	)
	defer rootSpan.End()

	var mu sync.Mutex
	results := make(map[string]map[string]scanner.Result, len(clients))
	for _, c := range clients {
		results[c.Context] = make(map[string]scanner.Result, len(scanners))
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, client := range clients {
		for name, sc := range scanners {
			// Check first: once ctx is done, a select with a free slot would still pick the
			// slot half the time.
			acquired := ctx.Err() == nil
			if acquired {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					acquired = false
				}
			}
			if !acquired {
				mu.Lock()
				results[client.Context][name] = scanner.ErroredResult(name, ctx.Err())
				mu.Unlock()
				continue
			}
			wg.Add(1)
			go func(c *kube.Client, scanName string, sc scanner.Scanner) {
				defer wg.Done()
				defer func() { <-sem }()

				spanCtx, span := tracing.Tracer().Start(ctx, "fleetsweeper.scanner."+scanName,
					trace.WithAttributes(
						attribute.String("fleetsweeper.cluster", c.Context),
						attribute.String("fleetsweeper.scanner", scanName),
					),
				)
				defer span.End()

				res, err := scanner.RunWithTimeout(spanCtx, sc, c, timeout)
				if err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, "scanner failed")
					log.Warn("scanner failed",
						zap.String("context", c.Context),
						zap.String("scanner", scanName),
						zap.Error(err),
					)
					res = scanner.ErroredResult(scanName, err)
				} else {
					span.SetStatus(codes.Ok, "")
				}

				mu.Lock()
				results[c.Context][scanName] = res
				mu.Unlock()
			}(client, name, sc)
		}
	}
	wg.Wait()
	return results
}
