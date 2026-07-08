package client

import (
	"encoding/json"
	"time"
)

// Severity is the severity of a finding or outlier.
type Severity string

// Severity levels reported by the API.
const (
	// SeverityCritical marks the most serious findings.
	SeverityCritical Severity = "critical"
	// SeverityWarning marks findings that warrant attention.
	SeverityWarning Severity = "warning"
	// SeverityInfo marks informational findings.
	SeverityInfo Severity = "info"
)

// ScanRecord is a persisted scan execution.
type ScanRecord struct {
	// ID is the unique, time-sortable scan identifier.
	ID string `json:"id"`
	// Timestamp is when the scan ran.
	Timestamp time.Time `json:"timestamp"`
	// Clusters are the cluster contexts included in the scan.
	Clusters []string `json:"clusters"`
	// Scanners are the scanner names that ran.
	Scanners []string `json:"scanners"`
}

// ScoreDriver explains one contribution to a FleetScore.
type ScoreDriver struct {
	// Reason is the human-readable driver description.
	Reason string `json:"reason"`
	// Impact is the point contribution to the score.
	Impact int `json:"impact"`
}

// FleetScore is the fleet-wide health grade.
type FleetScore struct {
	// Score is the 0 to 100 fleet health score.
	Score int `json:"score"`
	// Grade is the letter grade A through F.
	Grade string `json:"grade"`
	// Headline summarizes the fleet state.
	Headline string `json:"headline"`
	// Drivers lists the largest contributions to the score.
	Drivers []ScoreDriver `json:"drivers"`
}

// FleetScoreForecast projects a future fleet score from history.
type FleetScoreForecast struct {
	// Predicted is the projected score.
	Predicted int `json:"predicted"`
	// Lower is the lower bound of the prediction interval.
	Lower int `json:"lower"`
	// Upper is the upper bound of the prediction interval.
	Upper int `json:"upper"`
	// PredictedFor is the time the prediction targets.
	PredictedFor time.Time `json:"predicted_for"`
	// SlopePerHour is the fitted score change per hour.
	SlopePerHour float64 `json:"slope_per_hour"`
	// RSquared is the goodness of fit, 0 to 1.
	RSquared float64 `json:"r_squared"`
	// Basis is the number of history points behind the forecast.
	Basis int `json:"basis"`
	// Sufficient reports whether enough history backed the forecast.
	Sufficient bool `json:"sufficient"`
	// Headline summarizes the forecast.
	Headline string `json:"headline"`
}

// Remediation is the suggested fix for a finding.
type Remediation struct {
	// Command is a shell command that addresses the finding.
	Command string `json:"command,omitempty"`
	// YAML is a manifest snippet that addresses the finding.
	YAML string `json:"yaml,omitempty"`
	// RunbookURL links to operator documentation.
	RunbookURL string `json:"runbook_url,omitempty"`
}

// Finding is a single detected issue on a cluster.
type Finding struct {
	// Title is the short finding name.
	Title string `json:"title"`
	// Description explains the finding.
	Description string `json:"description,omitempty"`
	// Severity is the finding severity.
	Severity Severity `json:"severity"`
	// Cluster is the affected cluster context.
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produced the finding.
	Scanner string `json:"scanner"`
	// Affected lists the specific resources involved.
	Affected []string `json:"affected,omitempty"`
	// Remediation is the suggested fix, when available.
	Remediation *Remediation `json:"remediation,omitempty"`
}

// ClusterHealth is the rolled-up health of one cluster.
type ClusterHealth struct {
	// Name is the cluster context name.
	Name string `json:"name"`
	// Status is one of healthy, busy, degraded, or critical.
	Status string `json:"status"`
	// KubernetesVersion is the reported control-plane version.
	KubernetesVersion string `json:"kubernetes_version,omitempty"`
	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"node_count,omitempty"`
	// HealthyNodes is the number of ready nodes.
	HealthyNodes int `json:"healthy_nodes,omitempty"`
	// AvgCPU is the mean CPU utilization across nodes.
	AvgCPU float64 `json:"avg_cpu,omitempty"`
	// AvgMemory is the mean memory utilization across nodes.
	AvgMemory float64 `json:"avg_memory,omitempty"`
	// WarningEvents is the count of recent warning events.
	WarningEvents int `json:"warning_events,omitempty"`
	// NamespaceCount is the number of namespaces.
	NamespaceCount int `json:"namespace_count,omitempty"`
	// FindingCounts maps severity to the number of findings.
	FindingCounts map[string]int `json:"finding_counts,omitempty"`
}

// OutlierResult is one field on one cluster that deviates from the fleet norm.
type OutlierResult struct {
	// Cluster is the deviating cluster context.
	Cluster string `json:"cluster"`
	// Field is the metric that deviates.
	Field string `json:"field"`
	// Value is the cluster's value for the field.
	Value string `json:"value"`
	// FleetNorm is the fleet-typical value for the field.
	FleetNorm string `json:"fleet_norm"`
	// Deviation is the modified z-score distance from the norm.
	Deviation float64 `json:"deviation,omitempty"`
	// Scanner is the scanner that produced the metric.
	Scanner string `json:"scanner"`
	// Severity is the outlier severity.
	Severity Severity `json:"severity"`
}

// CapacityAnalysis is the capacity correlator output for one cluster.
type CapacityAnalysis struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster,omitempty"`
	// Status summarizes capacity pressure.
	Status string `json:"status,omitempty"`
	// CPUUtilization is the current CPU utilization.
	CPUUtilization float64 `json:"cpu_utilization,omitempty"`
	// MemoryUtilization is the current memory utilization.
	MemoryUtilization float64 `json:"memory_utilization,omitempty"`
	// NodeCount is the number of nodes.
	NodeCount int `json:"node_count,omitempty"`
	// HealthyNodes is the number of ready nodes.
	HealthyNodes int `json:"healthy_nodes,omitempty"`
	// HeadroomCPU is the remaining CPU headroom.
	HeadroomCPU float64 `json:"headroom_cpu,omitempty"`
	// HeadroomMemory is the remaining memory headroom.
	HeadroomMemory float64 `json:"headroom_memory,omitempty"`
	// HasMemoryPressure reports memory pressure on the cluster.
	HasMemoryPressure bool `json:"has_memory_pressure,omitempty"`
	// Recommendation is the suggested capacity action.
	Recommendation string `json:"recommendation,omitempty"`
}

// ReportSummary is the headline count block of a Report.
type ReportSummary struct {
	// ClusterCount is the number of clusters in the report.
	ClusterCount int `json:"cluster_count"`
	// ScannerCount is the number of scanners that reported.
	ScannerCount int `json:"scanner_count"`
	// UniformCount is the number of uniform sections.
	UniformCount int `json:"uniform_count"`
	// DivergentCount is the number of divergent sections.
	DivergentCount int `json:"divergent_count"`
	// TotalDivergences is the total divergence count.
	TotalDivergences int `json:"total_divergences"`
	// CriticalCount is the number of critical findings.
	CriticalCount int `json:"critical_count"`
	// WarningCount is the number of warning findings.
	WarningCount int `json:"warning_count"`
}

// Report is the full computed comparison report for a scan.
type Report struct {
	// Timestamp is when the underlying scan ran.
	Timestamp time.Time `json:"timestamp"`
	// Clusters are the cluster contexts in the report.
	Clusters []string `json:"clusters"`
	// Summary is the headline count block.
	Summary ReportSummary `json:"summary"`
	// FleetScore is the fleet-wide health grade.
	FleetScore FleetScore `json:"fleet_score"`
	// Findings are the detected issues across the fleet.
	Findings []Finding `json:"findings,omitempty"`
	// ClusterHealths are the per-cluster health rollups.
	ClusterHealths []ClusterHealth `json:"cluster_healths,omitempty"`
	// Outliers are the fleet-norm deviations.
	Outliers []OutlierResult `json:"outliers,omitempty"`
	// Capacity is the per-cluster capacity analysis.
	Capacity []CapacityAnalysis `json:"capacity,omitempty"`
}

// CostByCluster is the cost correlation for one cluster.
type CostByCluster struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster"`
	// Score is the cluster's fleet score.
	Score int `json:"score"`
	// CostUSD is the cluster's total cost in USD.
	CostUSD float64 `json:"cost_usd"`
	// DriftUSD is the cost attributed to drift in USD.
	DriftUSD float64 `json:"drift_usd"`
	// Period is the billing period label.
	Period string `json:"period,omitempty"`
}

// CostAnalysis is the fleet-wide cost correlation output.
type CostAnalysis struct {
	// Currency is the ISO currency code, for example USD.
	Currency string `json:"currency"`
	// Period is the billing period label.
	Period string `json:"period,omitempty"`
	// TotalFleetUSD is the total fleet cost in USD.
	TotalFleetUSD float64 `json:"total_fleet_usd"`
	// TotalDriftUSD is the total drift-attributed cost in USD.
	TotalDriftUSD float64 `json:"total_drift_usd"`
	// MissingCost lists clusters with no cost data.
	MissingCost []string `json:"missing_cost,omitempty"`
	// ByCluster is the per-cluster breakdown.
	ByCluster []CostByCluster `json:"by_cluster,omitempty"`
}

// IntegrationStatus reports whether one integration is configured.
type IntegrationStatus struct {
	// Name is the integration name.
	Name string `json:"name"`
	// Status is one of configured, off, or demo.
	Status string `json:"status"`
	// Hint explains how to enable the integration.
	Hint string `json:"hint,omitempty"`
}

// AckRequest is the body for acknowledging a finding.
type AckRequest struct {
	// Cluster narrows the ack to one cluster.
	Cluster string `json:"cluster,omitempty"`
	// Scanner narrows the ack to one scanner.
	Scanner string `json:"scanner,omitempty"`
	// Title narrows the ack to one finding title.
	Title string `json:"title,omitempty"`
	// AckBy identifies who acknowledged the finding.
	AckBy string `json:"ack_by,omitempty"`
	// Reason records why the finding was acknowledged.
	Reason string `json:"reason,omitempty"`
	// SnoozeUntil is an optional expiry; omit for a permanent ack.
	SnoozeUntil *time.Time `json:"snooze_until,omitempty"`
}

// AckRecord is a persisted acknowledgement.
type AckRecord struct {
	// Fingerprint is the acknowledged finding or alert fingerprint.
	Fingerprint string `json:"fingerprint"`
	// Cluster is the acknowledged cluster, when scoped.
	Cluster string `json:"cluster,omitempty"`
	// Scanner is the acknowledged scanner, when scoped.
	Scanner string `json:"scanner,omitempty"`
	// Title is the acknowledged finding title, when scoped.
	Title string `json:"title,omitempty"`
	// AckBy identifies who acknowledged the finding.
	AckBy string `json:"ack_by,omitempty"`
	// Reason records why the finding was acknowledged.
	Reason string `json:"reason,omitempty"`
	// SnoozeUntil is the ack expiry, zero for a permanent ack.
	SnoozeUntil time.Time `json:"snooze_until,omitempty"`
	// CreatedAt is when the ack was recorded.
	CreatedAt time.Time `json:"created_at"`
}

// AlertRecord is a persisted inbound alert from AlertManager or Falco.
type AlertRecord struct {
	// Fingerprint uniquely identifies the alert.
	Fingerprint string `json:"fingerprint"`
	// Cluster is the alerting cluster.
	Cluster string `json:"cluster"`
	// Status is firing or resolved.
	Status string `json:"status"`
	// Alertname is the alert rule name.
	Alertname string `json:"alertname"`
	// Severity is the alert severity label.
	Severity string `json:"severity,omitempty"`
	// Summary is the alert summary annotation.
	Summary string `json:"summary,omitempty"`
	// StartsAt is when the alert began firing.
	StartsAt time.Time `json:"starts_at,omitempty"`
	// EndsAt is when the alert resolved.
	EndsAt time.Time `json:"ends_at,omitempty"`
	// ReceivedAt is when the server ingested the alert.
	ReceivedAt time.Time `json:"received_at"`
	// Labels are the alert label set.
	Labels map[string]string `json:"labels"`
	// Annotations are the alert annotation set.
	Annotations map[string]string `json:"annotations"`
	// GeneratorURL links to the alert source.
	GeneratorURL string `json:"generator_url,omitempty"`
}

// ClusterRecord is a known cluster and when it was first and last seen.
type ClusterRecord struct {
	// Name is the cluster context name.
	Name string `json:"name"`
	// FirstSeen is when the cluster first appeared in a scan.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is when the cluster last appeared in a scan.
	LastSeen time.Time `json:"last_seen"`
}

// ClusterDetail is the full scanner data, health, and findings for a cluster.
type ClusterDetail struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster"`
	// ScanID is the scan the detail came from.
	ScanID string `json:"scan_id"`
	// ScanTime is when that scan ran.
	ScanTime time.Time `json:"scan_time"`
	// Health is the cluster health rollup.
	Health ClusterHealth `json:"health"`
	// Findings are the cluster's findings.
	Findings []Finding `json:"findings,omitempty"`
	// ScannerData is the raw per-scanner output, keyed by scanner name.
	ScannerData map[string]json.RawMessage `json:"scanner_data,omitempty"`
}

// OutliersResponse is the payload of GET /api/outliers.
type OutliersResponse struct {
	// ScanID is the scan the outliers came from.
	ScanID string `json:"scan_id"`
	// Outliers are the fleet-norm deviations.
	Outliers []OutlierResult `json:"outliers"`
	// Findings are the outlier-derived findings.
	Findings []Finding `json:"findings,omitempty"`
}

// CapacityResponse is the payload of GET /api/capacity.
type CapacityResponse struct {
	// ScanID is the scan the analysis came from.
	ScanID string `json:"scan_id"`
	// Capacity is the per-cluster analysis.
	Capacity []CapacityAnalysis `json:"capacity"`
}

// ForecastHistoryPoint is one score observation behind a fleet-score forecast.
type ForecastHistoryPoint struct {
	// ScanID is the scan the score came from.
	ScanID string `json:"scan_id"`
	// Timestamp is when that scan ran.
	Timestamp time.Time `json:"timestamp"`
	// Score is the fleet score at that time.
	Score int `json:"score"`
}

// FleetForecastResponse is the payload of GET /api/forecast/fleet-score.
type FleetForecastResponse struct {
	// History is the score observations behind the forecast.
	History []ForecastHistoryPoint `json:"history"`
	// Forecast is the projected next score.
	Forecast FleetScoreForecast `json:"forecast"`
}

// ClusterForecast is a per-cluster fleet-score forecast.
type ClusterForecast struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster"`
	// CurrentScore is the cluster's latest score.
	CurrentScore int `json:"current_score"`
	// Forecast is the projected next score.
	Forecast FleetScoreForecast `json:"forecast"`
}

// ClustersForecastResponse is the payload of GET /api/forecast/clusters.
type ClustersForecastResponse struct {
	// Forecasts are the per-cluster forecasts, ranked by projected delta.
	Forecasts []ClusterForecast `json:"forecasts"`
}

// AlertsResponse is the payload of GET /api/alerts.
type AlertsResponse struct {
	// Alerts are the matching inbound alerts.
	Alerts []AlertRecord `json:"alerts"`
	// Count is the number of alerts returned.
	Count int `json:"count"`
}

// TimelineEntry is one chronological event on a cluster.
type TimelineEntry struct {
	// Kind is scan, alert, or ack.
	Kind string `json:"kind"`
	// At is when the event occurred.
	At time.Time `json:"at"`
	// Severity is the event severity, when applicable.
	Severity string `json:"severity,omitempty"`
	// Title is the event title.
	Title string `json:"title,omitempty"`
	// Detail is the event detail text.
	Detail string `json:"detail,omitempty"`
	// Ref is an identifier linking back to the source record.
	Ref string `json:"ref,omitempty"`
}

// TimelineResponse is the payload of GET /api/clusters/{name}/timeline.
type TimelineResponse struct {
	// Cluster is the cluster the timeline describes.
	Cluster string `json:"cluster"`
	// Count is the number of entries returned.
	Count int `json:"count"`
	// Entries are the chronological events, newest first.
	Entries []TimelineEntry `json:"entries"`
}

// TriggerScanRequest is the body for POST /api/scans.
type TriggerScanRequest struct {
	// Contexts names the kubeconfig contexts to scan.
	Contexts []string `json:"contexts,omitempty"`
	// AllContexts scans every kubeconfig context when true.
	AllContexts bool `json:"all_contexts,omitempty"`
	// Group scans the clusters in a named group.
	Group string `json:"group,omitempty"`
}

// TriggerScanResponse is the payload returned when a scan is accepted.
type TriggerScanResponse struct {
	// ScanID identifies the accepted scan.
	ScanID string `json:"scan_id"`
	// Status is the acceptance status.
	Status string `json:"status"`
}

// Group is a named set of cluster contexts.
type Group struct {
	// Name is the group name.
	Name string `json:"name"`
	// Clusters are the cluster contexts in the group.
	Clusters []string `json:"clusters"`
}

// CreateGroupRequest is the body for POST /api/groups.
type CreateGroupRequest struct {
	// Name is the group name.
	Name string `json:"name"`
	// Clusters are the cluster contexts in the group.
	Clusters []string `json:"clusters,omitempty"`
}

// LocationRequest is the body for PUT /api/locations/{cluster}.
type LocationRequest struct {
	// Lat is the cluster latitude.
	Lat float64 `json:"lat"`
	// Lng is the cluster longitude.
	Lng float64 `json:"lng"`
	// Site is the human-readable site name.
	Site string `json:"site,omitempty"`
	// Notes is free-form operator text.
	Notes string `json:"notes,omitempty"`
}

// AckAlertRequest is the body for POST /api/alerts/{fingerprint}/ack.
type AckAlertRequest struct {
	// AckBy identifies who acknowledged the alert.
	AckBy string `json:"ack_by,omitempty"`
	// Reason records why the alert was acknowledged.
	Reason string `json:"reason,omitempty"`
	// SnoozeUntil is an optional expiry; omit for a permanent ack.
	SnoozeUntil *time.Time `json:"snooze_until,omitempty"`
}

// Context is a kubeconfig context available to the server.
type Context struct {
	// Name is the context name.
	Name string `json:"name"`
}
