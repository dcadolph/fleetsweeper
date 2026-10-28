package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner/policyreportingest"
)

// writeMetrics emits the Prometheus exposition for the server's current state
// to w. The function is structured top-down: counters that always exist first,
// then per-scan gauges, then per-cluster and per-finding labels. When no scan
// exists yet it emits only the counters and a comment so scrapers see a
// well-formed but mostly empty document instead of an error.
func (s *Server) writeMetrics(ctx context.Context, w io.Writer) {
	scansOK, scansErr := s.scanCounts()
	emit(w, "# HELP fleetsweeper_scans_total Total scans executed since startup, by result.")
	emit(w, "# TYPE fleetsweeper_scans_total counter")
	emit(w, fmt.Sprintf(`fleetsweeper_scans_total{result="success"} %d`, scansOK))
	emit(w, fmt.Sprintf(`fleetsweeper_scans_total{result="error"} %d`, scansErr))

	emit(w, "# HELP fleetsweeper_alerts_received_total Inbound alerts persisted since startup, by source.")
	emit(w, "# TYPE fleetsweeper_alerts_received_total counter")
	emit(w, fmt.Sprintf(`fleetsweeper_alerts_received_total{source="alertmanager"} %d`, s.alertsReceivedAM.Load()))
	emit(w, fmt.Sprintf(`fleetsweeper_alerts_received_total{source="falco"} %d`, s.alertsReceivedFalco.Load()))

	_, _ = s.admissionMetrics.WriteTo(w)

	dur := s.lastScanDuration.Load()
	if dur > 0 {
		emit(w, "# HELP fleetsweeper_last_scan_duration_seconds Duration of the most recent scan.")
		emit(w, "# TYPE fleetsweeper_last_scan_duration_seconds gauge")
		emit(w, fmt.Sprintf("fleetsweeper_last_scan_duration_seconds %.3f", float64(dur)/1e9))
	}

	r := s.latestReportForMetrics(ctx)
	if r == nil {
		emit(w, "# fleetsweeper: no scans available yet")
		controller.WriteMetrics(w)
		return
	}

	emit(w, "# HELP fleetsweeper_cluster_count Number of clusters in the most recent scan.")
	emit(w, "# TYPE fleetsweeper_cluster_count gauge")
	emit(w, fmt.Sprintf("fleetsweeper_cluster_count %d", len(r.Clusters)))

	emit(w, "# HELP fleetsweeper_fleet_score Fleet Score (0-100) from the most recent scan.")
	emit(w, "# TYPE fleetsweeper_fleet_score gauge")
	emit(w, fmt.Sprintf("fleetsweeper_fleet_score %d", r.FleetScore.Score))

	emit(w, "# HELP fleetsweeper_fleet_score_sample_clusters Clusters that contributed scanner data to the Fleet Score.")
	emit(w, "# TYPE fleetsweeper_fleet_score_sample_clusters gauge")
	emit(w, fmt.Sprintf("fleetsweeper_fleet_score_sample_clusters %d", r.FleetScore.SampleSize))

	emit(w, "# HELP fleetsweeper_fleet_score_dimensions Scan dimensions that contributed data to the Fleet Score.")
	emit(w, "# TYPE fleetsweeper_fleet_score_dimensions gauge")
	emit(w, fmt.Sprintf("fleetsweeper_fleet_score_dimensions %d", r.FleetScore.Dimensions))

	emit(w, "# HELP fleetsweeper_fleet_score_excluded_clusters Clusters excluded from the Fleet Score for insufficient data.")
	emit(w, "# TYPE fleetsweeper_fleet_score_excluded_clusters gauge")
	emit(w, fmt.Sprintf("fleetsweeper_fleet_score_excluded_clusters %d", r.FleetScore.ExcludedClusters))

	emit(w, "# HELP fleetsweeper_findings_total Total findings in the most recent scan by severity.")
	emit(w, "# TYPE fleetsweeper_findings_total gauge")
	var crit, warn, info int
	bySev := make(map[string]map[string]int)
	for _, f := range r.Findings {
		switch f.Severity {
		case report.SeverityCritical:
			crit++
		case report.SeverityWarning:
			warn++
		case report.SeverityInfo:
			info++
		}
		if bySev[f.Severity] == nil {
			bySev[f.Severity] = make(map[string]int)
		}
		bySev[f.Severity][f.Scanner]++
	}
	emit(w, fmt.Sprintf(`fleetsweeper_findings_total{severity="critical"} %d`, crit))
	emit(w, fmt.Sprintf(`fleetsweeper_findings_total{severity="warning"} %d`, warn))
	emit(w, fmt.Sprintf(`fleetsweeper_findings_total{severity="info"} %d`, info))

	emit(w, "# HELP fleetsweeper_finding_count Findings broken down by severity and scanner.")
	emit(w, "# TYPE fleetsweeper_finding_count gauge")
	for sev, perScanner := range bySev {
		for scanner, n := range perScanner {
			emit(w, fmt.Sprintf(
				`fleetsweeper_finding_count{severity=%q,scanner=%q} %d`,
				promLabelEscape(sev), promLabelEscape(scanner), n))
		}
	}

	emit(w, "# HELP fleetsweeper_cluster_health Cluster status indicator (1 = cluster is in that status, 0 = not).")
	emit(w, "# TYPE fleetsweeper_cluster_health gauge")
	statuses := []string{"healthy", "busy", "degraded", "critical"}
	for _, ch := range r.ClusterHealths {
		for _, st := range statuses {
			v := 0
			if ch.Status == st {
				v = 1
			}
			emit(w, fmt.Sprintf(
				`fleetsweeper_cluster_health{cluster=%q,status=%q} %d`,
				promLabelEscape(ch.Name), promLabelEscape(st), v))
		}
	}

	if len(r.Outliers) > 0 {
		emit(w, "# HELP fleetsweeper_outlier_score Modified z-score of an outlying cluster value. Outliers explained by a cohort are excluded.")
		emit(w, "# TYPE fleetsweeper_outlier_score gauge")
		for _, o := range r.Outliers {
			if len(o.ExplainedBy) > 0 {
				continue
			}
			emit(w, fmt.Sprintf(
				`fleetsweeper_outlier_score{cluster=%q,scanner=%q,field=%q,severity=%q} %.3f`,
				promLabelEscape(o.Cluster), promLabelEscape(o.Scanner),
				promLabelEscape(o.Field), promLabelEscape(o.Severity), o.Deviation))
		}
	}

	emit(w, "# HELP fleetsweeper_cluster_avg_cpu_percent Average CPU utilization per cluster.")
	emit(w, "# TYPE fleetsweeper_cluster_avg_cpu_percent gauge")
	emit(w, "# HELP fleetsweeper_cluster_avg_memory_percent Average memory utilization per cluster.")
	emit(w, "# TYPE fleetsweeper_cluster_avg_memory_percent gauge")
	for _, ch := range r.ClusterHealths {
		emit(w, fmt.Sprintf(`fleetsweeper_cluster_avg_cpu_percent{cluster=%q} %.2f`,
			promLabelEscape(ch.Name), ch.AvgCPU))
		emit(w, fmt.Sprintf(`fleetsweeper_cluster_avg_memory_percent{cluster=%q} %.2f`,
			promLabelEscape(ch.Name), ch.AvgMemory))
	}

	emitPolicyReportMetrics(w, r, s.log)

	controller.WriteMetrics(w)
}

// emitPolicyReportMetrics walks the policy-reports scanner output and
// exposes per-source result tallies as Prometheus gauges. Clusters whose data
// cannot be decoded are counted and reported once at Warn.
func emitPolicyReportMetrics(w io.Writer, r *report.Report, log *zap.Logger) {
	if r == nil || r.Sections == nil {
		return
	}
	sec, ok := r.Sections[policyreportingest.Name]
	if !ok || sec == nil || len(sec.PerCluster) == 0 {
		return
	}

	type tallyKey struct {
		Source, Result string
	}
	totals := map[tallyKey]int{}
	decodeFailures := 0
	for _, raw := range sec.PerCluster {
		blob, err := json.Marshal(raw)
		if err != nil {
			decodeFailures++
			continue
		}
		var d policyreportingest.Data
		if err := json.Unmarshal(blob, &d); err != nil {
			decodeFailures++
			continue
		}
		if !d.Available {
			continue
		}
		for _, ts := range d.BySource {
			totals[tallyKey{ts.Source, "pass"}] += ts.Pass
			totals[tallyKey{ts.Source, "fail"}] += ts.Fail
			totals[tallyKey{ts.Source, "warn"}] += ts.Warn
			totals[tallyKey{ts.Source, "error"}] += ts.Error
			totals[tallyKey{ts.Source, "skip"}] += ts.Skip
		}
	}
	if decodeFailures > 0 {
		log.Warn("metrics: decode policy report data", zap.Int("failures", decodeFailures))
	}
	if len(totals) == 0 {
		return
	}
	emit(w, "# HELP fleetsweeper_policy_results_total PolicyReport results aggregated across the fleet by producing tool and outcome.")
	emit(w, "# TYPE fleetsweeper_policy_results_total gauge")
	for k, n := range totals {
		emit(w, fmt.Sprintf(`fleetsweeper_policy_results_total{source=%q,result=%q} %d`,
			promLabelEscape(k.Source), promLabelEscape(k.Result), n))
	}
}

// latestReportForMetrics returns the rebuilt report for the most recent scan,
// or nil when no scan exists.
func (s *Server) latestReportForMetrics(ctx context.Context) *report.Report {
	scans, err := s.store.ListScans(ctx, 1)
	if err != nil {
		s.log.Warn("metrics: list scans", zap.Error(err))
		return nil
	}
	if len(scans) == 0 {
		return nil
	}

	latest := scans[0]
	results, err := s.store.GetScanResults(ctx, latest.ID)
	if err != nil {
		s.log.Warn("metrics: get scan results", zap.Error(err))
		return nil
	}
	opts := s.reportOptions(ctx, s.log)
	opts.Timestamp = latest.Timestamp
	return s.reports.get(latest.ID, latest.Clusters, results, opts)
}

// emit writes one line of Prometheus exposition followed by a newline.
func emit(w io.Writer, line string) {
	_, _ = io.WriteString(w, line)
	_, _ = io.WriteString(w, "\n")
}

// promLabelEscape escapes a Prometheus label value per the exposition format:
// backslash, double-quote, and newline must be escaped. We do not strip other
// characters because cluster and scanner names are operator-controlled
// identifiers, not free-form user input.
func promLabelEscape(v string) string {
	if !strings.ContainsAny(v, `\"`+"\n") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// recordScanDuration is invoked after a scan to update the last-scan-duration
// gauge surfaced via /metrics. Safe to call concurrently.
func (s *Server) recordScanDuration(d time.Duration) {
	s.lastScanDuration.Store(int64(d))
}
