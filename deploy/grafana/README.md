# Grafana dashboards

Drop these into a Grafana instance to visualise the metrics exposed by the
Fleetsweeper admin server.

## Prerequisites

Run the server with an admin address so `/metrics` is reachable:

```
fleetsweeper serve \
  --db fleet.db \
  --addr :8080 \
  --admin-addr 127.0.0.1:9090 \
  --auth-token "$TOKEN"
```

Scrape `127.0.0.1:9090/metrics` with Prometheus. A minimal scrape config:

```yaml
scrape_configs:
  - job_name: fleetsweeper
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

## Dashboards

| File                         | What it shows                                                                |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `fleet-overview.json`        | Fleet Score, cluster count, critical/warning counts, findings by scanner, per-cluster CPU/memory, scan duration. |
| `drift-trends.json`          | Fleet Score over time, findings volume, outlier z-scores per cluster, scan-duration trend. |
| `alerts.json`                | AlertManager + Falco ingest counts, ingest rate (5m), cumulative alerts by source. |

## Importing

### Manual upload

In Grafana: **Dashboards -> Import -> Upload JSON**. Select the file, pick
your Prometheus data source for the `PROM_DS` variable, and save.

### Grafana sidecar (kube-prometheus-stack)

When Grafana runs alongside Prometheus via the `grafana-sidecar` pattern
(kube-prometheus-stack's default), create a labeled ConfigMap containing
the dashboard JSON and the sidecar picks them up automatically:

```bash
kubectl -n monitoring create configmap fleetsweeper-dashboards \
  --from-file=deploy/grafana/ \
  --dry-run=client -o yaml | \
kubectl label --local -f - --overwrite grafana_dashboard=1 -o yaml | \
kubectl apply -f -
```

The exact label depends on how your Grafana sidecar is configured —
`grafana_dashboard=1` is the kube-prometheus-stack default.

The dashboards use only labels that the Fleetsweeper `/metrics` endpoint
already emits. No recording rules are required.

## Metric reference

| Metric                                            | Type    | Labels                                  |
| ------------------------------------------------- | ------- | --------------------------------------- |
| `fleetsweeper_scans_total`                        | counter | `result`                                |
| `fleetsweeper_cluster_count`                      | gauge   | (none)                                  |
| `fleetsweeper_fleet_score`                        | gauge   | (none)                                  |
| `fleetsweeper_findings_total`                     | gauge   | `severity`                              |
| `fleetsweeper_finding_count`                      | gauge   | `severity`, `scanner`                   |
| `fleetsweeper_cluster_health`                     | gauge   | `cluster`, `status`                     |
| `fleetsweeper_cluster_avg_cpu_percent`            | gauge   | `cluster`                               |
| `fleetsweeper_cluster_avg_memory_percent`         | gauge   | `cluster`                               |
| `fleetsweeper_outlier_score`                      | gauge   | `cluster`, `scanner`, `field`, `severity` |
| `fleetsweeper_last_scan_duration_seconds`         | gauge   | (none)                                  |
| `fleetsweeper_alerts_received_total`              | counter | `source` (alertmanager, falco)          |
| `fleetsweeper_policy_results_total`               | gauge   | `source`, `result` (pass/fail/warn/error/skip) |
