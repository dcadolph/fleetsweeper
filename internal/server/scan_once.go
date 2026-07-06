package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// ScanOnce executes a single scan with the given options and returns a summary.
// It satisfies the controller.ScanRunner interface so the ClusterScan operator
// can drive scans without depending on internal server types beyond Server.
// Concurrent calls are serialized by the same mutex that gates HTTP triggers
// so a controller-driven scan and an operator-driven scan cannot interleave.
func (s *Server) ScanOnce(ctx context.Context, opts controller.ScanOptions) (controller.ScanSummary, error) {
	contexts, err := s.resolveOptionContexts(ctx, opts)
	if err != nil {
		return controller.ScanSummary{}, err
	}
	if len(contexts) == 0 {
		return controller.ScanSummary{}, errors.New("scan once: no contexts to scan")
	}

	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	started := time.Now()
	s.log.Info("controller scan starting",
		zap.String("resource", opts.ResourceName),
		zap.Int("contexts", len(contexts)),
	)

	clients := kube.ConnectAll(ctx, s.kubeconfigPath, contexts, s.workers)
	if len(clients) == 0 {
		return controller.ScanSummary{}, errors.New("scan once: no clusters reachable")
	}

	scanners := s.selectScanners(opts.Scanners)
	if len(scanners) == 0 {
		return controller.ScanSummary{}, errors.New("scan once: no scanners selected")
	}

	results := runScanners(ctx, clients, scanners, s.workers, s.log)
	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	scanID, err := s.store.SaveScan(ctx, clusterNames, results)
	if err != nil {
		s.scansErr.Add(1)
		s.recordScanCompletion(false)
		return controller.ScanSummary{}, fmt.Errorf("save scan: %w", err)
	}
	s.scansOK.Add(1)
	s.recordScanDuration(time.Since(started))
	s.recordScanCompletion(true)

	tags := projectCohortTags(ctx, s, cohortTagKey)
	rpt := report.Build(clusterNames, results, report.BuildOptions{ClusterTags: tags})
	if opts.Emit.Slack {
		s.notifySlackForReport(ctx, rpt)
	}
	if opts.Emit.FleetDriftReport {
		s.writeFleetDriftIfConfigured(rpt, scanID)
	}
	if opts.Emit.PolicyReport {
		s.writePolicyReportIfConfigured(rpt, scanID)
	}
	s.dispatchWebhooksIfConfigured(ctx, rpt)

	return controller.ScanSummary{
		ScanID:   scanID,
		Score:    rpt.FleetScore.Score,
		Grade:    rpt.FleetScore.Grade,
		Critical: countFindings(rpt, report.SeverityCritical),
		Warning:  countFindings(rpt, report.SeverityWarning),
		Clusters: len(clusterNames),
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
