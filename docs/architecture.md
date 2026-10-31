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
                       │ scanners (24)    │
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

## Packages

Every package in the module, other than the `main` entry point. A test keeps this
table in step with the tree, so a new package needs a row here.

| Package                               | Role                                                                                            |
|---------------------------------------|-------------------------------------------------------------------------------------------------|
| `client`                              | Go SDK for the HTTP API. Public, so its import path is stable.                                  |
| `cmd`                                 | Cobra command line interface. Every subcommand lives here.                                      |
| `internal/admission`                  | Validating admission webhook that warns on or denies pods that deviate from the fleet baseline. |
| `internal/browser`                    | Dashboard browser smoke test, built only with the `browser` tag.                                |
| `internal/cohort`                     | Splits a fleet into groups of clusters that look like each other.                               |
| `internal/compare`                    | Diffs two reports: score change, new, resolved, and persisting findings.                        |
| `internal/controller`                 | Reconciles ClusterScan resources and writes results back to their status.                       |
| `internal/cost`                       | Correlates findings and cluster scores with a cost CSV.                                         |
| `internal/diagnose`                   | End-to-end sanity check of every configured integration.                                        |
| `internal/explain`                    | Operator-facing explanations for findings and scanners.                                         |
| `internal/fleetdrift`                 | Writes FleetDriftReport resources as YAML, one per cluster.                                     |
| `internal/integration`                | Integration tests on real kind clusters, built only with the `integration` tag.                 |
| `internal/jsonutil`                   | JSON output for commands, compact by default and indented on request.                           |
| `internal/kube`                       | client-go connection helpers and concurrent fan-out across contexts.                            |
| `internal/leader`                     | Lease-based leader election for the controller.                                                 |
| `internal/logutil`                    | Threads a zap logger through a context.                                                         |
| `internal/podsec`                     | Evaluates pod security fields with Kubernetes precedence for scanners and admission.            |
| `internal/policyreport`               | Converts findings into wgpolicyk8s.io PolicyReport resources.                                   |
| `internal/remediate`                  | Opens a pull request against a GitOps repo from a finding's YAML remediation.                   |
| `internal/report`                     | Builds the report: comparisons, outliers, findings, cluster health, scores, trends.             |
| `internal/scanner`                    | Scanner interface, result and coverage types, and the registry.                                 |
| `internal/scanner/admission`          | Admission webhooks with no healthy endpoints or an expiring caBundle.                           |
| `internal/scanner/certs`              | TLS Secret, Ingress TLS, and webhook caBundle expiry.                                           |
| `internal/scanner/clusterinfo`        | Node OS, kernel, runtime, kubelet, and kube-proxy versions, and drift within a cluster.         |
| `internal/scanner/crd`                | Installed CustomResourceDefinitions.                                                            |
| `internal/scanner/deprecatedapis`     | In-use API versions that Kubernetes deprecated or removed.                                      |
| `internal/scanner/events`             | Recent warning events per namespace.                                                            |
| `internal/scanner/geo`                | Cluster location from node region and zone labels.                                              |
| `internal/scanner/imageaudit`         | Image digest pinning, latest tags, distinct images, and optional registry probes.               |
| `internal/scanner/ingress`            | Ingress resources.                                                                              |
| `internal/scanner/metrics`            | Node utilization from the metrics.k8s.io API.                                                   |
| `internal/scanner/namespace`          | Namespaces.                                                                                     |
| `internal/scanner/networkpolicy`      | NetworkPolicy coverage.                                                                         |
| `internal/scanner/nodehealth`         | Node health conditions.                                                                         |
| `internal/scanner/policyreportingest` | Fail and warn results from PolicyReports other tools wrote.                                     |
| `internal/scanner/quota`              | ResourceQuota and LimitRange coverage.                                                          |
| `internal/scanner/rbac`               | RBAC graph counts, wildcard permissions, and broad bindings.                                    |
| `internal/scanner/rbacaudit`          | Over-permissive bindings and rules, including cluster-admin grants.                             |
| `internal/scanner/resources`          | Node capacity and conditions.                                                                   |
| `internal/scanner/security`           | Pod Security labels, default-deny policies, and similar hardening signals.                      |
| `internal/scanner/service`            | Services.                                                                                       |
| `internal/scanner/version`            | Kubernetes server version and fleet-wide skew.                                                  |
| `internal/scanner/vulnerabilities`    | Trivy Operator VulnerabilityReport severity counts.                                             |
| `internal/scanner/workloadcoverage`   | PDB and HPA coverage of replicated workloads.                                                   |
| `internal/scanner/workloadsec`        | Pod security contexts across all namespaces.                                                    |
| `internal/seal`                       | HMAC-SHA256 sealing for export bundles.                                                         |
| `internal/server`                     | HTTP API and the embedded dashboard over the scan store.                                        |
| `internal/store`                      | Scans, results, and fleet records in SQLite or Postgres.                                        |
| `internal/testcerts`                  | Self-signed certificates for tests.                                                             |
| `internal/tracing`                    | OpenTelemetry tracer provider from the standard OTLP environment variables.                     |
| `internal/util`                       | Small helpers shared across packages.                                                           |
| `internal/webhooks`                   | Outbound webhook subscribers notified after every scan.                                         |

## Where to go next

- [Scanners](concepts/scanners.md). The 24 dimensions checked per cluster.
- [Fleet Score](concepts/fleet-score.md). How the 0-100 number is computed.
- [Outliers](concepts/outliers.md). MAD-based outlier detection details.
