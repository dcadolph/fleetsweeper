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

Scanning is read-only: fleetsweeper lists and gets, and never changes a
scanned cluster's workloads or configuration. Everything it writes is listed
here:

- The SQLite or Postgres database.
- Local YAML files (FleetDriftReport, PolicyReport) when emission is on.
- In the cluster running the controller: the `.status` of ClusterScan
  resources, Kubernetes Events on them, and a Lease for leader election.
- Admission responses: in enforce mode the webhook denies pods that deviate
  from the fleet baseline. In the default warn mode it only adds warnings.
- Outbound calls you configured: the Slack webhook, outbound webhook
  subscribers, and OpenTelemetry exporters.
- Pull requests against a GitOps repo you control, only when you run
  `fleetsweeper remediate --push`.

## Where to go next

- [Scanners](concepts/scanners.md). The 24 dimensions checked per cluster.
- [Fleet Score](concepts/fleet-score.md). How the 0-100 number is computed.
- [Outliers](concepts/outliers.md). MAD-based outlier detection details.
