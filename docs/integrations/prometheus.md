# Prometheus and Grafana

Fleetsweeper exposes Prometheus metrics on the admin server and ships a
starter Grafana dashboard.

## Enable

```yaml
serve:
  args:
    - --admin-addr=:8081
```

Then scrape `:8081/metrics`. The admin endpoint also exposes pprof at
`/debug/pprof/*` for performance debugging.

## Metric families

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `fleetsweeper_scans_total` | counter | `result` (`success`, `error`) | Scans executed since startup. |
| `fleetsweeper_alerts_received_total` | counter | `source` (`alertmanager`, `falco`) | Inbound alerts persisted since startup. |
| `fleetsweeper_last_scan_duration_seconds` | gauge | none | Duration of the most recent scan. Emitted once a scan has run since startup. |
| `fleetsweeper_cluster_count` | gauge | none | Clusters in the most recent scan. |
| `fleetsweeper_fleet_score` | gauge | none | Fleet Score (0-100) from the most recent scan. Absent while the scan is not graded. |
| `fleetsweeper_fleet_score_graded` | gauge | none | 1 when the scan observed enough of the fleet to grade it, 0 otherwise. |
| `fleetsweeper_coverage_ratio` | gauge | none | Share of expected scanner runs that observed the fleet (0-1). |
| `fleetsweeper_fleet_score_sample_clusters` | gauge | none | Clusters that contributed scanner data to the Fleet Score. |
| `fleetsweeper_fleet_score_dimensions` | gauge | none | Scan dimensions that contributed data to the Fleet Score. |
| `fleetsweeper_fleet_score_excluded_clusters` | gauge | none | Clusters excluded from the Fleet Score for insufficient data. |
| `fleetsweeper_findings_total` | gauge | `severity` | Findings in the most recent scan by severity. |
| `fleetsweeper_finding_count` | gauge | `severity`, `scanner` | Findings in the most recent scan by severity and scanner. |
| `fleetsweeper_cluster_health` | gauge | `cluster`, `status` | One series per cluster and status. The series for the cluster's current status is 1, the others are 0. Statuses are `healthy`, `busy`, `unknown`, `degraded`, and `critical`. `unknown` means a scanner run did not observe the cluster and no finding made it degraded or critical. |
| `fleetsweeper_outlier_score` | gauge | `cluster`, `scanner`, `field`, `severity` | Modified z-score of an outlying cluster value in the most recent scan. Held outliers (explained by a cohort) are excluded. |
| `fleetsweeper_cluster_avg_cpu_percent` | gauge | `cluster` | Average CPU utilization per cluster. |
| `fleetsweeper_cluster_avg_memory_percent` | gauge | `cluster` | Average memory utilization per cluster. |
| `fleetsweeper_policy_results_total` | gauge | `source`, `result` (`pass`, `fail`, `warn`, `error`, `skip`) | PolicyReport results aggregated across the fleet. Emitted only when the policy-reports scanner returned data. |
| `fleetsweeper_admission_decisions_total` | counter | `mode`, `decision` | Admission decisions since startup. |
| `fleetsweeper_admission_check_failures_total` | counter | `check` | Pods that fired a fleet-norm check since startup. |
| `fleetsweeper_controller_reconcile_total` | counter | none | Reconcile passes the ClusterScan controller has performed. |
| `fleetsweeper_controller_reconcile_outcome_total` | counter | `outcome` (`success`, `failure`) | Reconcile passes by outcome. |
| `fleetsweeper_controller_scans_total` | counter | `result` (`triggered`, `success`, `failure`) | Scans the controller has triggered. |
| `fleetsweeper_controller_paused_resources` | counter | none | Resources observed with `spec.paused=true` on the most recent reconcile cycle. |

## Starter dashboards

`deploy/grafana/fleet-overview.json` ships a starter dashboard with:

- Fleet Score.
- Clusters in fleet.
- Critical findings and warning findings.
- Cluster health distribution.
- Findings by scanner.
- Average CPU and average memory per cluster.
- Scans per second (5m rate).
- Last scan duration.

`deploy/grafana/drift-trends.json` ships a second dashboard with:

- Fleet Score over time.
- Findings by severity.
- Outliers by cluster (modified z-score).
- Findings volume by scanner (critical and warning).
- Scan duration (last completion).

`deploy/grafana/alerts.json` charts inbound alerts: AlertManager alerts and Falco events
ingested, the 5m ingest rate, and cumulative alerts by source.

Import via Grafana → Dashboards → New → Import → upload JSON.

## OpenTelemetry traces

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, fleetsweeper emits one span per
scanner per cluster as children of the per-scan root span. Combined with
the metrics this gives operators a complete picture of where a slow scan
is spending time.
