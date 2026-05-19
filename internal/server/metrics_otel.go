package server

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/tracing"
)

// otelMetrics owns the OTel metric instruments registered for the server.
// When no OTel endpoint is configured the global meter is a no-op, so the
// instruments still exist but never export.
type otelMetrics struct {
	// scanCounter increments once per scan completion.
	scanCounter metric.Int64Counter
}

// initOTelMetrics registers Fleetsweeper metric instruments with the global
// OTel meter and wires observable callbacks that read the most recent scan.
// Errors are returned to the caller; the caller should log and continue so
// startup never blocks on metric setup.
func (s *Server) initOTelMetrics() error {
	m := tracing.Meter()

	scanCounter, err := m.Int64Counter("fleetsweeper.scans.total",
		metric.WithDescription("Total scans executed since startup, by result."))
	if err != nil {
		return err
	}
	s.otel.scanCounter = scanCounter

	fleetScore, err := m.Int64ObservableGauge("fleetsweeper.fleet.score",
		metric.WithDescription("Fleet Score (0-100) from the most recent scan."))
	if err != nil {
		return err
	}
	clusterCount, err := m.Int64ObservableGauge("fleetsweeper.cluster.count",
		metric.WithDescription("Number of clusters in the most recent scan."))
	if err != nil {
		return err
	}
	findingsTotal, err := m.Int64ObservableGauge("fleetsweeper.findings.total",
		metric.WithDescription("Total findings in the most recent scan by severity."))
	if err != nil {
		return err
	}
	clusterHealth, err := m.Int64ObservableGauge("fleetsweeper.cluster.health",
		metric.WithDescription("Per-cluster health status (1 = matches status, 0 otherwise)."))
	if err != nil {
		return err
	}
	cpuPercent, err := m.Float64ObservableGauge("fleetsweeper.cluster.cpu.percent",
		metric.WithDescription("Average CPU utilization per cluster."))
	if err != nil {
		return err
	}
	memPercent, err := m.Float64ObservableGauge("fleetsweeper.cluster.memory.percent",
		metric.WithDescription("Average memory utilization per cluster."))
	if err != nil {
		return err
	}
	scanDuration, err := m.Float64ObservableGauge("fleetsweeper.scan.duration.seconds",
		metric.WithDescription("Duration of the most recent scan."),
		metric.WithUnit("s"))
	if err != nil {
		return err
	}

	_, err = m.RegisterCallback(func(ctx context.Context, obs metric.Observer) error {
		// Last-scan duration is available even without a stored report.
		if d := s.lastScanDuration.Load(); d > 0 {
			obs.ObserveFloat64(scanDuration, float64(d)/1e9)
		}
		r := s.latestReportForMetrics(ctx)
		if r == nil {
			return nil
		}
		obs.ObserveInt64(fleetScore, int64(r.FleetScore.Score))
		obs.ObserveInt64(clusterCount, int64(len(r.Clusters)))

		bySev := map[string]int{
			report.SeverityCritical: 0,
			report.SeverityWarning:  0,
			report.SeverityInfo:     0,
		}
		for _, f := range r.Findings {
			bySev[f.Severity]++
		}
		for sev, n := range bySev {
			obs.ObserveInt64(findingsTotal, int64(n),
				metric.WithAttributes(attribute.String("severity", sev)))
		}

		statuses := []string{"healthy", "busy", "degraded", "critical"}
		for _, ch := range r.ClusterHealths {
			for _, st := range statuses {
				v := int64(0)
				if ch.Status == st {
					v = 1
				}
				obs.ObserveInt64(clusterHealth, v, metric.WithAttributes(
					attribute.String("cluster", ch.Name),
					attribute.String("status", st),
				))
			}
			obs.ObserveFloat64(cpuPercent, ch.AvgCPU,
				metric.WithAttributes(attribute.String("cluster", ch.Name)))
			obs.ObserveFloat64(memPercent, ch.AvgMemory,
				metric.WithAttributes(attribute.String("cluster", ch.Name)))
		}
		return nil
	}, fleetScore, clusterCount, findingsTotal, clusterHealth,
		cpuPercent, memPercent, scanDuration)
	return err
}

// recordScanCompletion bumps the OTel scan counter with the result attribute.
// Safe to call even when initOTelMetrics has not run; the counter is created
// against the no-op meter in that case.
func (s *Server) recordScanCompletion(success bool) {
	if s.otel.scanCounter == nil {
		return
	}
	result := "success"
	if !success {
		result = "error"
	}
	s.otel.scanCounter.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("result", result)))
}

// otelInitField is the Server struct field for the otelMetrics block. Kept in
// this file so the metrics code is self-contained and the server.go imports
// list does not grow.
type otelInitField = otelMetrics

// initOTelMetricsOrLog calls initOTelMetrics and downgrades any error to a
// log. Metric initialization failures must never abort server startup.
func (s *Server) initOTelMetricsOrLog() {
	if err := s.initOTelMetrics(); err != nil {
		s.log.Warn("otel metrics init failed", zap.Error(err))
	}
}
