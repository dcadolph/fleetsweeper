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

| Metric | Type | Description |
| --- | --- | --- |
| `fleetsweeper_fleet_score` | gauge | Current 0-100 Fleet Score. |
| `fleetsweeper_cluster_health_status` | gauge | One series per cluster, value is 0 (healthy), 1 (busy), 2 (degraded), 3 (critical). |
| `fleetsweeper_findings_total` | counter | Per `severity` and `scanner` label. |
| `fleetsweeper_scan_duration_seconds` | histogram | Per-scan duration. |
| `fleetsweeper_scan_completed_total` | counter | Per `result` label (`success` or `error`). |
| `fleetsweeper_outlier_score` | gauge | Per-cluster MAD score on the most recent scan. |

## Starter dashboard

`deploy/grafana/fleet-overview.json` ships a starter dashboard with:

- Fleet Score gauge with grade-coloured thresholds.
- Cluster health heatmap.
- Findings by severity over time.
- Scan duration p95.
- Outlier table (top 10).

Import via Grafana → Dashboards → New → Import → upload JSON.

## OpenTelemetry traces

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, fleetsweeper emits one span per
scanner per cluster as children of the per-scan root span. Combined with
the metrics this gives operators a complete picture of where a slow scan
is spending time.
