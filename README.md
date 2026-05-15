# fleetsweeper

A multi-cluster Kubernetes fleet comparison tool. Fleetsweeper connects to your clusters, scans their configuration and state, and produces a structured report highlighting differences, health issues, and drift across the fleet.

## What it does

Fleetsweeper scans multiple Kubernetes clusters in parallel and compares them across 13 dimensions:

| Scanner | What it checks |
| ------- | -------------- |
| Kubernetes Version | API server version divergence across clusters |
| Namespaces | Namespace lists, labels, and Pod Security Standards labels |
| Services | All services across all namespaces, types, and ports |
| Ingresses | Ingress resources, classes, TLS configuration, and hosts |
| RBAC | ClusterRoles, Roles, and all bindings |
| Pod Security | PSS enforcement labels on every namespace |
| Network Policies | NetworkPolicy coverage per namespace |
| Resource Quotas | ResourceQuota and LimitRange objects |
| CRDs | Installed CustomResourceDefinitions |
| Node Resources | Node count, allocatable CPU and memory, scheduling status |
| Node Health | Node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure |
| Resource Utilization | Real-time CPU and memory usage from metrics-server |
| Events | Warning events aggregated by reason with recent event details |

For every scanner, fleetsweeper compares the data across clusters and flags divergences with severity levels (critical, warning, info). It translates raw data into plain English findings like "prod-eu-central has 2 nodes under memory pressure" instead of just showing a number.

## Output formats

**JSON** to stdout for scripting and pipelines. Compact by default, indented with `--pretty`.

**HTML** report as a self-contained dashboard file with charts, filters, cluster health cards, and findings.

**Server mode** with a web UI and REST API backed by SQLite for scan history, trend tracking, cluster grouping, and outlier detection.

## Installation

```
go install github.com/dcadolph/fleetsweeper@latest
```

Or build from source:

```
git clone https://github.com/dcadolph/fleetsweeper.git
cd fleetsweeper
go build -o fleetsweeper .
```

## Quick start

Scan all clusters in your kubeconfig and print a JSON report:

```
fleetsweeper scan --all-contexts --pretty
```

Scan specific clusters:

```
fleetsweeper scan --contexts prod-east,prod-west,staging --pretty
```

Generate an HTML report:

```
fleetsweeper scan --all-contexts -o html --html-file report.html
```

## Persisting scan results

Pass `--db` to store results in a SQLite database. This enables scan history, trend analysis, and cluster grouping.

```
fleetsweeper scan --all-contexts --db fleet.db
```

Run multiple scans over time to build history:

```
fleetsweeper scan --all-contexts --db fleet.db   # Monday
fleetsweeper scan --all-contexts --db fleet.db   # Wednesday
fleetsweeper scan --all-contexts --db fleet.db   # Friday
```

## Cluster grouping

Create named groups of clusters for targeted scanning and comparison.

```
fleetsweeper group create production --clusters prod-east,prod-west,prod-eu --db fleet.db
fleetsweeper group create staging --clusters staging-us,staging-eu --db fleet.db
fleetsweeper group list --db fleet.db
```

Scan only a group:

```
fleetsweeper scan --group production --db fleet.db --pretty
```

Manage group membership:

```
fleetsweeper group add-cluster production --clusters prod-asia --db fleet.db
fleetsweeper group remove-cluster staging --clusters staging-eu --db fleet.db
fleetsweeper group delete staging --db fleet.db
```

## Scan history and trends

Browse past scans, compare them, and analyze drift over time.

```
fleetsweeper history list --db fleet.db
fleetsweeper history show <scan-id> --db fleet.db --pretty
fleetsweeper history diff <scan-id-1> <scan-id-2> --db fleet.db --pretty
```

View fleet drift trends (requires at least 2 stored scans):

```
fleetsweeper history trend --db fleet.db
fleetsweeper history trend --cluster prod-east --db fleet.db
```

Trend analysis uses linear regression to determine if metrics are stable, improving, or worsening. It produces findings like "memory utilization on prod-eu-central has been rising steadily."

## Outlier detection

When scanning more than 20 clusters, fleetsweeper automatically switches from pairwise comparison to statistical outlier detection. Instead of listing every difference between every pair of clusters, it identifies the clusters that deviate from the fleet norm.

The detection uses median absolute deviation (MAD) for numeric fields, mode detection for string fields, and consensus set analysis for list fields. Tune sensitivity with `--outlier-threshold` (lower values flag more outliers):

```
fleetsweeper scan --all-contexts --db fleet.db --outlier-threshold 2.5
```

## Server mode

Start a web server with a dashboard and REST API:

```
fleetsweeper serve --db fleet.db --addr :8080
```

With scheduled automatic scanning:

```
fleetsweeper serve --db fleet.db --scan-interval 30m --all-contexts
```

The dashboard provides:

- Fleet overview with clickable summary cards that drill down into divergent scanners and findings
- Cluster health cards with CPU and memory gauges
- Findings with severity, descriptions, and suggested kubectl remediation commands
- Scan history browser
- Trend analysis
- Outlier detection
- Cluster grouping
- CSV export for findings and cluster data

<details>
<summary>API endpoints</summary>

```
GET    /api/scans                  List scans (with ?limit=N)
GET    /api/scans/{id}             Get scan metadata
GET    /api/scans/{id}/report      Get full computed report for a scan
POST   /api/scans                  Trigger a new scan
GET    /api/clusters               List all known clusters
GET    /api/clusters/{name}/detail Full scanner data for a cluster
GET    /api/groups                 List groups
POST   /api/groups                 Create a group
DELETE /api/groups/{name}          Delete a group
GET    /api/trends                 Fleet trend analysis
GET    /api/trends/{cluster}       Per-cluster trend analysis
GET    /api/outliers               Outlier detection on latest scan
```

</details>

## Findings and remediation

Fleetsweeper translates raw scan data into actionable findings. Each finding includes a severity level, a plain English description, and for critical and warning findings, suggested kubectl commands to investigate or resolve the issue.

Examples of findings:

| Severity | Finding | Remediation |
| -------- | ------- | ----------- |
| Critical | prod-eu has 2 nodes under memory pressure | `kubectl --context prod-eu top nodes` |
| Critical | staging is running a different Kubernetes version | `kubectl --context staging version --short` |
| Warning | dev has 5 namespaces without Pod Security enforcement | `kubectl --context dev get ns -L pod-security.kubernetes.io/enforce` |
| Warning | prod-eu has 110 warning events | `kubectl --context prod-eu get events --field-selector type=Warning --sort-by=.lastTimestamp` |
| Info | prod-east: all 6 nodes healthy | No action needed |

## Integration tests

Integration tests use kind (Kubernetes in Docker) to create real clusters with divergent configurations. They require Docker to be running and kind to be installed.

```
brew install kind
go test -tags=integration -timeout=10m ./internal/integration/
```

The tests create two kind clusters, seed them with different namespaces, services, RBAC rules, network policies, security labels, and resource quotas, then run all scanners and validate the comparison report.

## License

MIT
