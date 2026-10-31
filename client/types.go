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
	// SampleSize is the number of clusters that contributed scanner data.
	SampleSize int `json:"sample_size"`
	// Dimensions is the number of scan dimensions that contributed data.
	Dimensions int `json:"dimensions"`
	// ExcludedClusters is how many clusters were excluded for insufficient data.
	ExcludedClusters int `json:"excluded_clusters"`
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
	// Rule names the check that produced the finding as scanner/slug. It names
	// no cluster and no count, so the same check on two clusters shares a rule.
	Rule string `json:"rule"`
	// Fingerprint is the stable finding identifier and the ack key: the
	// SHA-256 of cluster, scanner, and rule.
	Fingerprint string `json:"fingerprint"`
	// Acked reports whether an active acknowledgement covers the finding.
	Acked bool `json:"acked"`
	// Affected lists the specific resources involved.
	Affected []string `json:"affected,omitempty"`
	// Remediation is the suggested fix, when available.
	Remediation *Remediation `json:"remediation,omitempty"`
	// Norm is the fleet or cohort norm a fleet-relative finding was measured
	// against. It is nil on absolute-rule findings.
	Norm *NormBasis `json:"norm,omitempty"`
}

// NormBasis states the norm a fleet-relative finding was measured against.
// Which fields apply depends on Kind.
type NormBasis struct {
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Field is the scanner field the norm describes.
	Field string `json:"field"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Exact marks a numeric norm with zero spread, judged like a string. An exact norm
	// carries no z-score and no band.
	Exact bool `json:"exact,omitempty"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the members of a set field present in at least
	// Threshold of the population, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied: the modified z-score for
	// numeric, the minimum mode share for string, and the minimum presence
	// share for set membership.
	Threshold float64 `json:"threshold"`
	// Value is this cluster's value for the field.
	Value string `json:"value"`
	// Z is this cluster's signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
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
	// DegradedScanners is how many scanner runs did not return complete data for
	// this cluster. Nonzero means the cluster's report rests on partial coverage.
	DegradedScanners int `json:"degraded_scanners,omitempty"`
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
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Exact marks a numeric norm with zero spread, judged like a string. An exact norm
	// carries no z-score and no band.
	Exact bool `json:"exact,omitempty"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the consensus members of a set field, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied (see NormBasis.Threshold).
	Threshold float64 `json:"threshold"`
	// Z is the signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// Favorable marks a numeric outlier on the better side of a field with a polarity. It is
	// reported at info severity.
	Favorable bool `json:"favorable,omitempty"`
	// ExplainedBy names the operator-tagged cohort whose own norm holds this
	// fleet outlier, empty otherwise. An explained outlier raises no finding.
	ExplainedBy string `json:"explained_by,omitempty"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
}

// CapacityAnalysis is the capacity correlator output for one cluster.
type CapacityAnalysis struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster,omitempty"`
	// Status summarizes capacity pressure.
	Status string `json:"status,omitempty"`
	// CPUUtilization is the current CPU utilization, nil when no scanner observed it.
	CPUUtilization *float64 `json:"cpu_utilization,omitempty"`
	// MemoryUtilization is the current memory utilization, nil when no scanner observed it.
	MemoryUtilization *float64 `json:"memory_utilization,omitempty"`
	// NodeCount is the number of nodes.
	NodeCount int `json:"node_count,omitempty"`
	// HealthyNodes is the number of ready nodes.
	HealthyNodes int `json:"healthy_nodes,omitempty"`
	// HeadroomCPU is the remaining CPU headroom, nil when utilization was not observed.
	HeadroomCPU *float64 `json:"headroom_cpu,omitempty"`
	// HeadroomMemory is the remaining memory headroom, nil when utilization was not observed.
	HeadroomMemory *float64 `json:"headroom_memory,omitempty"`
	// HasMemoryPressure reports memory pressure on the cluster.
	HasMemoryPressure bool `json:"has_memory_pressure,omitempty"`
	// HasDiskPressure reports disk pressure on the cluster.
	HasDiskPressure bool `json:"has_disk_pressure"`
	// HasOOMEvents reports that OOMKilling events were detected.
	HasOOMEvents bool `json:"has_oom_events"`
	// HasSchedulingFailures reports that FailedScheduling events were detected.
	HasSchedulingFailures bool `json:"has_scheduling_failures"`
	// Recommendation is the suggested capacity action.
	Recommendation string `json:"recommendation,omitempty"`
	// NodesNeededForTarget is how many additional nodes would bring memory below 70%.
	NodesNeededForTarget int `json:"nodes_needed_for_target,omitempty"`
	// GroupDeviation describes how this cluster compares to its group peers.
	GroupDeviation string `json:"group_deviation,omitempty"`
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
	// Notes explain analysis the report could not run.
	Notes []string `json:"notes,omitempty"`
	// Distributions holds the population behind every field the detectors
	// evaluated, fleet scope first, most deviant first.
	Distributions []Distribution `json:"distributions,omitempty"`
	// DeviationMass sums, per cluster, the capped |z| of its fleet-scope
	// numeric values.
	DeviationMass map[string]float64 `json:"deviation_mass,omitempty"`
	// ScoreAttribution is the cost ledger behind FleetScore.
	ScoreAttribution *ScoreAttribution `json:"score_attribution,omitempty"`
	// Cohorts partitions the fleet with within-cohort outliers.
	Cohorts []CohortSummary `json:"cohorts,omitempty"`
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

// AckRequest is the body for acknowledging a finding. The server takes the
// cluster, scanner, and title from the finding it holds.
type AckRequest struct {
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
	// Acked reports whether an active acknowledgement covers the alert.
	Acked bool `json:"acked"`
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
	// Peers lists the five nearest clusters on the cohort map.
	Peers []Peer `json:"peers,omitempty"`
	// Distributions lists every distribution that flags the cluster.
	Distributions []Distribution `json:"distributions,omitempty"`
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

// ScannerInfo describes one scanner.
type ScannerInfo struct {
	// ID is the scanner key used in reports and findings.
	ID string `json:"id"`
	// Label is the human-readable name.
	Label string `json:"label"`
	// Description says in one line what the scanner checks.
	Description string `json:"description"`
	// Category is the report category the scanner belongs to.
	Category string `json:"category"`
}

// CohortSummary is one cohort of the fleet and its within-cohort outliers.
type CohortSummary struct {
	// Name is the tag value, "auto-N", or "fleet".
	Name string `json:"name"`
	// Source is tagged, auto, or fleet.
	Source string `json:"source"`
	// Clusters lists the members, sorted.
	Clusters []string `json:"clusters"`
	// Outliers are clusters that deviate from the cohort's own norm.
	Outliers []OutlierResult `json:"outliers,omitempty"`
}

// CohortsResponse is the body of GET /api/cohorts.
type CohortsResponse struct {
	// ScanID is the scan the cohorts came from.
	ScanID string `json:"scan_id"`
	// Cohorts partitions the fleet.
	Cohorts []CohortSummary `json:"cohorts"`
}

// Distribution is the population a detector measured one field against.
type Distribution struct {
	// Scope is "fleet" or a cohort name.
	Scope string `json:"scope"`
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// Kind is numeric, string, or set.
	Kind string `json:"kind"`
	// Values holds one entry per cluster in the population.
	Values []ClusterValue `json:"values"`
	// Median is the median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field.
	MAD float64 `json:"mad"`
	// Exact marks a numeric norm with zero spread, judged like a string. An exact norm
	// carries no z-score and no band.
	Exact bool `json:"exact,omitempty"`
	// Band is how far from the median a numeric value may sit before it flags.
	Band float64 `json:"band"`
	// Threshold is the cutoff the detector applied.
	Threshold float64 `json:"threshold"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the share of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the members of a set field most clusters have.
	Consensus []string `json:"consensus,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// LimitedSample marks a population too small for MAD.
	LimitedSample bool `json:"limited_sample,omitempty"`
	// Mass is the sum of |z| capped at 10 per value.
	Mass float64 `json:"mass"`
}

// ClusterValue is one cluster's value in a Distribution.
type ClusterValue struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Number is the value of a numeric field.
	Number *float64 `json:"number,omitempty"`
	// Text is the value of a string field.
	Text string `json:"text,omitempty"`
	// Size is how many members a set field has on this cluster.
	Size int `json:"size,omitempty"`
	// Missing lists the consensus members this cluster lacks.
	Missing []string `json:"missing,omitempty"`
	// Z is the signed modified z-score of a numeric value.
	Z float64 `json:"z,omitempty"`
	// Outlier is true when the detector flagged this cluster.
	Outlier bool `json:"outlier,omitempty"`
	// Explained names the cohort whose own norm explains this outlier, empty otherwise.
	Explained string `json:"explained,omitempty"`
}

// DistributionsResponse is the body of GET /api/distributions.
type DistributionsResponse struct {
	// ScanID is the scan the distributions came from.
	ScanID string `json:"scan_id"`
	// Distributions are the matching distributions, most deviant first.
	Distributions []Distribution `json:"distributions"`
}

// DistributionQuery filters GET /api/distributions. Empty fields match all,
// and an empty Scope means fleet.
type DistributionQuery struct {
	// Scope is "fleet", a cohort name, or "*" for every scope.
	Scope string
	// Scanner restricts to one scanner.
	Scanner string
	// Field restricts to one field.
	Field string
}

// HistoryPoint is one scan's distribution of a field.
type HistoryPoint struct {
	// ScanID is the scan.
	ScanID string `json:"scan_id"`
	// Timestamp is when the scan ran.
	Timestamp time.Time `json:"timestamp"`
	// Distribution is the field's distribution in that scan, nil when absent.
	Distribution *Distribution `json:"distribution"`
}

// HistoryResponse is the body of GET /api/distributions/history.
type HistoryResponse struct {
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// Scope is the norm scope.
	Scope string `json:"scope"`
	// Points lists the distribution per scan, oldest first.
	Points []HistoryPoint `json:"points"`
}

// ScoreAttribution is the cost ledger behind a fleet score.
type ScoreAttribution struct {
	// Terms lists every term that cost points.
	Terms []ScoreTerm `json:"terms"`
	// Entries lists every contribution to a term.
	Entries []ScoreEntry `json:"entries"`
	// Total is the sum of applied costs.
	Total float64 `json:"total"`
	// ByCluster sums applied cost per cluster.
	ByCluster map[string]float64 `json:"by_cluster,omitempty"`
	// ByRule sums applied cost per finding rule.
	ByRule map[string]float64 `json:"by_rule,omitempty"`
}

// ScoreTerm is one cost category of the fleet score.
type ScoreTerm struct {
	// Term names the category.
	Term string `json:"term"`
	// Reason is the driver label.
	Reason string `json:"reason"`
	// Count is how many findings or clusters the term charged.
	Count int `json:"count"`
	// Raw is the cost before the cap.
	Raw float64 `json:"raw"`
	// Cap is the most the term may cost, zero when uncapped.
	Cap float64 `json:"cap,omitempty"`
	// Cost is the points the term removed.
	Cost float64 `json:"cost"`
}

// ScoreEntry is one contribution to a score term.
type ScoreEntry struct {
	// Term is the category.
	Term string `json:"term"`
	// Rule is the finding rule charged, if any.
	Rule string `json:"rule,omitempty"`
	// Cluster is the cluster charged, if any.
	Cluster string `json:"cluster,omitempty"`
	// Raw is the cost before the cap.
	Raw float64 `json:"raw"`
	// Cost is the cost after the cap.
	Cost float64 `json:"cost"`
}

// AttributionResponse is the body of GET /api/score/attribution.
type AttributionResponse struct {
	// ScanID is the scan the score came from.
	ScanID string `json:"scan_id"`
	// Score is the fleet score.
	Score FleetScore `json:"score"`
	// Attribution is the ledger behind it.
	Attribution *ScoreAttribution `json:"attribution"`
}

// DriftLedger is the body of GET /api/drift.
type DriftLedger struct {
	// Scans lists the scan IDs spanned, oldest first.
	Scans []string `json:"scans"`
	// Clusters lists the clusters that drifted, largest change first.
	Clusters []ClusterDrift `json:"clusters"`
}

// ClusterDrift is one cluster's row in the drift ledger.
type ClusterDrift struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Mass is the deviation mass per scan, oldest first.
	Mass []float64 `json:"mass"`
	// MassBefore is the deviation mass in the first scan.
	MassBefore float64 `json:"mass_before"`
	// MassAfter is the deviation mass in the last scan.
	MassAfter float64 `json:"mass_after"`
	// MassDelta is MassAfter - MassBefore.
	MassDelta float64 `json:"mass_delta"`
	// Fields lists the fields whose values changed most.
	Fields []FieldDrift `json:"fields,omitempty"`
	// Gained lists outlier flags gained.
	Gained []FlagChange `json:"gained,omitempty"`
	// Lost lists outlier flags lost.
	Lost []FlagChange `json:"lost,omitempty"`
}

// FieldDrift is one field's movement for one cluster.
type FieldDrift struct {
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// ZBefore is the z in the first scan.
	ZBefore float64 `json:"z_before"`
	// ZAfter is the z in the last scan.
	ZAfter float64 `json:"z_after"`
	// Before is the value in the first scan.
	Before string `json:"before,omitempty"`
	// After is the value in the last scan.
	After string `json:"after,omitempty"`
}

// FlagChange is an outlier flag that changed state.
type FlagChange struct {
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// Scan is where the flag last flipped.
	Scan string `json:"scan"`
}

// DriftQuery selects the window of GET /api/drift: the last Scans scans, or
// the scans between Since and Until when either is set.
type DriftQuery struct {
	// Scans is how many recent scans to span. Zero uses the server default.
	Scans int
	// Since is the start of a time window.
	Since time.Time
	// Until is the end of a time window.
	Until time.Time
}

// Peer is a nearby cluster on the cohort map.
type Peer struct {
	// Cluster is the peer's name.
	Cluster string `json:"cluster"`
	// Distance is the feature distance.
	Distance float64 `json:"distance"`
}

// MapPoint is one cluster on the cohort map.
type MapPoint struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Cohort is the cluster's cohort.
	Cohort string `json:"cohort"`
	// X is the first coordinate.
	X float64 `json:"x"`
	// Y is the second coordinate.
	Y float64 `json:"y"`
	// Peers lists the nearest clusters.
	Peers []Peer `json:"peers,omitempty"`
}

// CohortMap is the two-dimensional layout of a fleet.
type CohortMap struct {
	// Points holds one entry per cluster.
	Points []MapPoint `json:"points"`
	// LeafOrder lists clusters with each cohort contiguous.
	LeafOrder []string `json:"leaf_order"`
	// Stress is the misfit of the layout, 0 when exact.
	Stress float64 `json:"stress"`
}

// CohortMapResponse is the body of GET /api/cohorts/map.
type CohortMapResponse struct {
	// ScanID is the scan the map came from.
	ScanID string `json:"scan_id"`
	// Map is the layout.
	Map CohortMap `json:"map"`
}

// WhatIfRequest is the body of POST /api/whatif.
type WhatIfRequest struct {
	// Cluster is the cluster to fix.
	Cluster string `json:"cluster"`
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field to fix.
	Field string `json:"field"`
	// Fix is median, mode, consensus, or remove. Empty picks one.
	Fix string `json:"fix,omitempty"`
	// Scope is "fleet" or a cohort name.
	Scope string `json:"scope,omitempty"`
	// Scan is the scan to project from. Empty means the latest.
	Scan string `json:"scan,omitempty"`
}

// WhatIfFix is the fix a projection applied, with kind and scope resolved.
type WhatIfFix struct {
	// Cluster is the fixed cluster.
	Cluster string `json:"cluster"`
	// Scanner is the scanner of the field.
	Scanner string `json:"scanner"`
	// Field is the field.
	Field string `json:"field"`
	// Kind is the fix kind applied.
	Kind string `json:"kind"`
	// Scope is the norm scope.
	Scope string `json:"scope"`
}

// WhatIfOutcome is the projected result of a fix.
type WhatIfOutcome struct {
	// Fix is the applied fix.
	Fix WhatIfFix `json:"fix"`
	// ScoreBefore is the score as scanned.
	ScoreBefore int `json:"score_before"`
	// ScoreAfter is the score after the fix.
	ScoreAfter int `json:"score_after"`
	// Before is the field's distribution as scanned.
	Before *Distribution `json:"before"`
	// After is the field's distribution after the fix, nil when every cluster agrees.
	After *Distribution `json:"after,omitempty"`
	// MedianShift is the change in the median.
	MedianShift float64 `json:"median_shift"`
	// MADShift is the change in the MAD.
	MADShift float64 `json:"mad_shift"`
	// NewOutliers lists clusters newly flagged.
	NewOutliers []string `json:"new_outliers,omitempty"`
	// ClearedOutliers lists clusters no longer flagged.
	ClearedOutliers []string `json:"cleared_outliers,omitempty"`
}

// WhatIfResponse is the body returned by POST /api/whatif.
type WhatIfResponse struct {
	// ScanID is the scan the projection started from.
	ScanID string `json:"scan_id"`
	// Outcome is the projection.
	Outcome WhatIfOutcome `json:"outcome"`
}
