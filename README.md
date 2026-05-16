<p align="center">
  <img src="internal/logo/sweep.jpg" alt="fleetsweeper" width="280">
</p>

# fleetsweeper

A multi-cluster Kubernetes fleet comparison tool. Fleetsweeper connects to your clusters, scans their configuration and state, and produces a structured report highlighting differences, health issues, and drift across the fleet.

## What it does

Fleetsweeper scans multiple Kubernetes clusters in parallel and compares them across 16 dimensions:

| Scanner            | What it checks |
| ------------------ | -------------- |
| Kubernetes Version | API server version divergence across clusters, with semver-aware severity |
| Namespaces         | Namespace lists, labels, and Pod Security Standards labels |
| Services           | All services across all namespaces, types, and ports |
| Ingresses          | Ingress resources, classes, TLS configuration, and hosts |
| RBAC               | ClusterRoles, Roles, and all bindings |
| Pod Security       | PSS enforcement labels on every namespace |
| Network Policies   | NetworkPolicy coverage per namespace |
| Resource Quotas    | ResourceQuota and LimitRange objects |
| CRDs               | Installed CustomResourceDefinitions |
| Node Resources     | Node count, allocatable CPU and memory, scheduling status |
| Node Health        | Node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure |
| Resource Utilization | Real-time CPU and memory from metrics-server (Quantity-aware parsing) |
| Events             | Warning events in the last hour, aggregated by reason |
| Workload Security  | Privileged containers, host namespaces, capabilities, seccomp, hostPath, runAs |
| RBAC Audit         | Cluster-admin bindings, wildcard rules, default-SA bindings, RoleBinding audit |
| Image Audit        | :latest tags, missing digest pins, image pull policies |

For every scanner, fleetsweeper compares the data across clusters and flags divergences with severity levels (critical, warning, info). Findings name the specific offending nodes, pods, bindings, and images so operators can act without spelunking the JSON.

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

Container image:

```
docker pull ghcr.io/dcadolph/fleetsweeper:latest
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

## Cluster grouping

Create named groups of clusters for targeted scanning and comparison.

```
fleetsweeper group create production --clusters prod-east,prod-west,prod-eu --db fleet.db
fleetsweeper group list --db fleet.db
fleetsweeper scan --group production --db fleet.db --pretty
```

## Scan history, trends, and pruning

Browse past scans, compare them, and analyze drift over time.

```
fleetsweeper history list --db fleet.db
fleetsweeper history show <scan-id> --db fleet.db --pretty
fleetsweeper history diff <scan-id-1> <scan-id-2> --db fleet.db --pretty
fleetsweeper history trend --db fleet.db
fleetsweeper history trend --cluster prod-east --db fleet.db
```

Trends use OLS linear regression on elapsed time, with R-squared and slope t-statistic gating so noisy or sparse data does not flip a direction. Findings include a `confidence` field and require at least five points before reporting non-stable directions.

Prune old scans (cascades to scan_results) and reclaim disk:

```
fleetsweeper history prune --older-than 30d --vacuum --db fleet.db
fleetsweeper history prune --older-than 7d --dry-run --db fleet.db
```

## Outlier detection

When scanning more than 20 clusters and a section has at least 8 reporting values, fleetsweeper switches from pairwise comparison to statistical outlier detection using median absolute deviation (MAD). Sample-size and MAD-zero gates suppress findings on near-uniform integer data. String fields require the mode to hold at least 60% of the population before minority values are flagged.

Tune sensitivity with `--outlier-threshold` (lower flags more outliers):

```
fleetsweeper scan --all-contexts --db fleet.db --outlier-threshold 2.5
```

## Server mode

Start a web server with a dashboard and REST API:

```
fleetsweeper serve --db fleet.db --addr :8080 --auth-token "$(openssl rand -hex 32)"
```

With scheduled automatic scanning and admin endpoints on a separate address:

```
fleetsweeper serve \
  --db fleet.db \
  --scan-interval 30m \
  --all-contexts \
  --auth-token "$TOKEN" \
  --cors-origin https://fleet.internal \
  --admin-addr 127.0.0.1:9090
```

The dashboard provides:

- Fleet overview with summary cards
- Cluster health cards with CPU and memory gauges
- Findings with severity, named affected resources, and suggested kubectl remediation
- Scan history browser and diff
- Trend analysis with confidence
- Outlier detection
- Cluster grouping
- CSV export for findings and cluster data

<details>
<summary>API endpoints</summary>

```
GET    /healthz                  Liveness probe (unauthenticated)
GET    /readyz                   Readiness probe (pings the store)
GET    /api/scans                List scans (with ?limit=N)
GET    /api/scans/{id}           Get scan metadata
GET    /api/scans/{id}/report    Get full computed report for a scan
POST   /api/scans                Trigger a new scan (auth required)
GET    /api/clusters             List all known clusters
GET    /api/clusters/{name}/detail Full scanner data for a cluster
GET    /api/groups               List groups
POST   /api/groups               Create a group (auth required)
DELETE /api/groups/{name}        Delete a group (auth required)
GET    /api/trends               Fleet trend analysis
GET    /api/trends/{cluster}     Per-cluster trend analysis
GET    /api/outliers             Outlier detection on latest scan
GET    /api/capacity             Capacity correlator output for latest scan
```

The admin server (when `--admin-addr` is set) additionally exposes `/debug/pprof/*`, `/metrics`, `/healthz`, and `/readyz`. Keep this address on an internal interface.

</details>

## Security

By default, mutating endpoints (`POST /api/scans`, `POST /api/groups`, `DELETE /api/groups/...`) return 403 because `serve` will scan whatever kubeconfig the process holds. Two ways to allow mutations:

1. **Recommended**: set `--auth-token` to a long random string. Clients must send `Authorization: Bearer <token>` on mutating requests. Comparison is constant-time.
2. **Explicit opt-out**: pass `--insecure` to disable authentication entirely. A loud warning is logged at startup.

CORS is refused by default; pass `--cors-origin https://your-ui` (repeatable) to allow explicit origins. Wildcard origins are intentionally not supported.

Error responses returned to clients are sanitized; full error detail is logged via structured logging.

## Findings and remediation

Fleetsweeper translates raw scan data into actionable findings. Each finding includes:

- A severity level (critical, warning, info)
- The specific affected resources (named nodes, pods, bindings, images)
- A plain English description
- A parameterized `kubectl` command using the affected resource names, when applicable
- Embedded YAML manifests for "no NetworkPolicy" and "no ResourceQuota" findings

Severity calibration is conservative on purpose:

- Kubernetes version differences are info for patch-only skew, warning for single-minor, critical only when skew exceeds one minor (outside the upstream skew policy).
- ClusterRoleCount divergence is warning, not critical, because cloud add-ons legitimately differ.
- Maximum CPU and memory percentages are warning, since natural per-cluster variation should not page an SRE.

Examples of findings:

| Severity | Finding | Remediation |
| -------- | ------- | ----------- |
| Critical | prod-eu has 2 nodes under memory pressure | `kubectl --context prod-eu describe node n-12 n-17` |
| Warning  | Kubernetes version skew across fleet | `kubectl version --short` |
| Warning  | prod-eu has 7 warning events in the last hour | `kubectl --context prod-eu get events --field-selector type=Warning ...` |
| Warning  | dev has 5 namespaces without Pod Security enforcement | `kubectl --context dev label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite` |

## Globe view

The dashboard ships a 3D fleet globe at `#/globe`. Each cluster is rendered as a point colored by health status (healthy/busy/degraded/critical). Critical clusters pulse red and the camera focuses on them after load so a status TV draws the eye to trouble first. Click a point to drill into the cluster detail page.

Cluster locations are resolved in this order, highest priority first:

1. **Manual override in the fleetsweeper database** — set via CLI or REST. Best when you don't control the target cluster's manifests.
2. **In-cluster ConfigMap `kube-system/fleetsweeper`** — best when you do control the cluster. Lives with the cluster, GitOps-friendly, travels with kustomize/Helm/Argo.
3. **In-cluster namespace annotations** on `kube-system` — same idea as the ConfigMap, useful when your provisioning already patches the namespace.
4. **Auto-detect from cloud-region node labels** — the default fallback. The `geo` scanner reads `topology.kubernetes.io/region` on every node and maps known AWS, GCP, Azure, DigitalOcean, OCI, IBM, and Alibaba regions to approximate centroids. Zero configuration for managed clusters.

### CLI override

```
fleetsweeper location set store-nyc-42 --lat 40.7589 --lng -73.9851 --site "Store #42, Times Square" --db fleet.db
fleetsweeper location list --db fleet.db
fleetsweeper location delete store-nyc-42 --db fleet.db
```

### In-cluster override via ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fleetsweeper
  namespace: kube-system
data:
  lat: "40.7589"
  lng: "-73.9851"
  site: "Store #42, Times Square"
  notes: "Flagship retail location."
```

Apply with `kubectl --context <cluster> apply -f deploy/examples/location-configmap.yaml`. Fleetsweeper reads this on every scan; updates take effect on the next scan.

### In-cluster override via namespace annotations

```
kubectl --context <cluster> annotate namespace kube-system \
  fleetsweeper.io/lat=40.7589 \
  fleetsweeper.io/lng=-73.9851 \
  fleetsweeper.io/site="Store #42, Times Square" \
  --overwrite
```

The globe surfaces which source each placement came from so operators can see whether a cluster is showing its auto-detected region, an in-cluster override, or a database override.

The server-side endpoints behind the globe are:

```
GET    /api/geo                       Cluster placements + health for the latest scan
GET    /api/locations                 List all manual overrides
PUT    /api/locations/{cluster}       Upsert a manual override (auth required)
DELETE /api/locations/{cluster}       Delete a manual override (auth required)
```

## In-cluster deployment

A minimal least-privilege ClusterRole, ServiceAccount, and binding is provided in `deploy/rbac.yaml`. Apply it before deploying the controller workload:

```
kubectl create namespace fleetsweeper
kubectl apply -f deploy/rbac.yaml
```

The Helm chart at `deploy/helm/fleetsweeper` packages the same RBAC plus a `Deployment`, `Service`, optional `PersistentVolumeClaim` for the SQLite database, and an auth-token `Secret`. Install with:

```
helm install fleetsweeper deploy/helm/fleetsweeper \
  --namespace fleetsweeper --create-namespace \
  --set auth.token="$(openssl rand -hex 32)"
```

When `--kubeconfig` is empty and the process detects an in-cluster service account, fleetsweeper uses `rest.InClusterConfig()` automatically. Scanning external clusters from inside a pod is also supported by mounting a kubeconfig Secret and passing `--kubeconfig`.

## Required RBAC

Fleetsweeper reads cluster state only; it never writes. The ClusterRole in `deploy/rbac.yaml` enumerates exactly which API resources require `get/list/watch` permission. Audit this file before deploying with cluster-admin credentials.

## Integration tests

Integration tests use kind (Kubernetes in Docker) to create real clusters with divergent configurations. They require Docker and kind.

```
brew install kind
go test -tags=integration -timeout=10m ./internal/integration/
```

## License

MIT. See `LICENSE`.
