# Architecture

Fleetsweeper is a pipeline, not a kitchen-sink. The same data flow runs
whether you invoke `scan` from a terminal or run `serve` continuously.

```
                       ┌──────────────────┐
                       │ kubeconfig       │
                       │ (N contexts)     │
                       └────────┬─────────┘
                                │
                       ┌────────▼─────────┐
                       │ scanners (16)    │
                       │ parallel, read-  │
                       │ only, per-cluster│
                       └────────┬─────────┘
                                │ raw per-cluster data
                       ┌────────▼─────────┐
                       │ report.Build     │
                       │ - compare        │
                       │ - severity       │
                       │ - outliers (MAD) │
                       │ - findings       │
                       │ - cluster health │
                       │ - Fleet Score    │
                       │ - capacity       │
                       └────────┬─────────┘
                                │ Report{}
        ┌───────────────┬───────┴────────┬────────────────┬──────────────┐
        │               │                │                │              │
   ┌────▼────┐    ┌─────▼─────┐    ┌─────▼──────┐   ┌─────▼─────┐  ┌─────▼─────┐
   │  JSON   │    │   HTML    │    │  SQLite    │   │  Web UI   │  │ exports   │
   │ stdout  │    │  report   │    │  store     │   │ + globe   │  │ tar.gz    │
   └─────────┘    └───────────┘    └─────┬──────┘   └─────┬─────┘  └───────────┘
                                          │                │
                                  ┌───────┴────────┐       │
                                  │ trends / OLS   │       │
                                  │ forecasts      │       │
                                  └────────────────┘       │
                                                            │
        ┌────────────┬──────────────┬───────────────┬───────┴──────┬──────────────┐
        │            │              │               │              │              │
   ┌────▼────┐  ┌────▼─────┐  ┌─────▼──────┐  ┌─────▼──────┐ ┌─────▼─────┐  ┌─────▼─────┐
   │ /metrics│  │ OTel     │  │ Slack      │  │ Policy-    │ │ FleetDrift│  │ Cost CSV  │
   │ (Prom)  │  │ traces+  │  │ webhook    │  │ Report     │ │ Reports   │  │ correl.   │
   │         │  │ metrics  │  │ (criticals)│  │ YAMLs      │ │ YAMLs     │  │           │
   └─────────┘  └──────────┘  └────────────┘  └────────────┘ └───────────┘  └───────────┘
```

The scanners produce raw data. The report builder turns that data into
human-readable findings, a per-cluster health summary, an outlier list, a
capacity analysis, and a single Fleet Score (0-100). Everything downstream
is a sink for the same Report: a JSON dump, an HTML page, a row in SQLite
that enables history and forecasting, an OTel span, a Slack message, or a
YAML CR your GitOps tool reconciles.

## Write boundary

Fleetsweeper never writes to the clusters it scans. The only write paths
are:

- The local SQLite or Postgres database.
- Local YAML files (FleetDriftReport, PolicyReport).
- The Slack webhook you configured.
- OpenTelemetry exporters you pointed it at.
- Pull requests against a GitOps repo you control, only when you explicitly run `fleetsweeper remediate --push`.

## Where to go next

- [Scanners](concepts/scanners.md). The 24 dimensions checked per cluster.
- [Fleet Score](concepts/fleet-score.md). How the 0-100 number is computed.
- [Outliers](concepts/outliers.md). MAD-based outlier detection details.
