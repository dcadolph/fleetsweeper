# Getting Started

The quickstart below puts a dashboard on screen in about a minute. The rest of
this page is the full walkthrough, from a real scan to the in-cluster controller.

## 60-second quickstart

Install the binary and boot a demo dashboard against a synthetic fleet. No
kubeconfig required.

```shell
go install github.com/dcadolph/fleetsweeper@latest
fleetsweeper serve --demo --addr :8080
```

Open <http://localhost:8080>. The `--demo` fleet renders the globe, findings,
trends, and outliers with no cluster access.

Swap the synthetic fleet for your own: run a scan, then restart the server
against the same database. `--insecure` disables auth for local viewing.

```shell
fleetsweeper scan --all-contexts --db /tmp/fleet.db
fleetsweeper serve --db /tmp/fleet.db --insecure
```

Refresh the dashboard. The Fleet Score recomputes from your clusters and the
demo fleet drops away. That is the whole loop; the sections below break down
each piece.

## Prerequisites

- A kubeconfig with at least two cluster contexts (so there is fleet-wide
  data to compare).
- Go 1.26 to build from source, or the prebuilt container at
  `ghcr.io/dcadolph/fleetsweeper:latest`.

## Run the dashboard locally

```shell
fleetsweeper serve --db /tmp/fleet.db --insecure --demo
```

The `--demo` flag preloads a synthetic fleet so the dashboard, globe, and
trend charts have something to render on first boot. The `--insecure` flag
disables authentication, which is appropriate only when you are testing
locally.

Open <http://localhost:8080>.

## Run a real scan

```shell
fleetsweeper scan --db /tmp/fleet.db --all-contexts
```

Then refresh the dashboard. The Fleet Score updates with real data; the
demo fleet is hidden once a real scan exists.

## Authenticate the API

Replace `--insecure` with `--auth-token <random>` for a development bearer
token, or mint a scoped key:

```shell
fleetsweeper apikey create --db /tmp/fleet.db \
  --name ci-runner \
  --role operator \
  --scope 'group:prod' \
  --ttl 720h
```

The raw token is printed exactly once. Save it in your secret store and use
it as `Authorization: Bearer <token>` for every API call.

## Enable the controller

If fleetsweeper runs in-cluster, install the CRD and turn on the controller:

```shell
kubectl apply -f deploy/crds/clusterscan.yaml
kubectl apply -f deploy/examples/clusterscan-prod.yaml
```

Inspect status with `kubectl get clusterscan`. The controller writes
`phase`, `observedScore`, `observedCritical`, and `lastScanTime` back to
each resource after every scan.

## Output formats

- **JSON** to stdout for scripting and pipelines. Compact by default, indented with `--pretty`.
- **HTML** report as a self-contained dashboard file with charts, filters, cluster health cards, and findings.
- **Server mode** with a web UI and REST API backed by SQLite for scan history, trend tracking, cluster grouping, and outlier detection.

Generate an HTML report:

```shell
fleetsweeper scan --all-contexts -o html --html-file report.html
```

## Persist scan results

Pass `--db` to store results in a SQLite database. This enables scan
history, trend analysis, and cluster grouping.

```shell
fleetsweeper scan --all-contexts --db fleet.db
```

## Cluster groups

Create named groups for targeted scanning and comparison.

```shell
fleetsweeper group create production \
  --clusters prod-east,prod-west,prod-eu --db fleet.db
fleetsweeper group list --db fleet.db
fleetsweeper scan --group production --db fleet.db --pretty
```

## History and trends

Browse past scans, compare them, and analyze drift over time.

```shell
fleetsweeper history list --db fleet.db
fleetsweeper history show <scan-id> --db fleet.db --pretty
fleetsweeper history diff <scan-id-1> <scan-id-2> --db fleet.db --pretty
fleetsweeper history trend --db fleet.db
fleetsweeper history trend --cluster prod-east --db fleet.db
```

Trends use OLS linear regression on elapsed time, with R-squared and slope
t-statistic gating so noisy or sparse data does not flip a direction.
Findings include a `confidence` field and require at least five points
before reporting non-stable directions.

Prune old scans and reclaim disk:

```shell
fleetsweeper history prune --older-than 30d --vacuum --db fleet.db
fleetsweeper history prune --older-than 7d --dry-run --db fleet.db
```

## Tune outlier sensitivity

When scanning more than 20 clusters and a section has at least 8 reporting
values, fleetsweeper switches from pairwise comparison to statistical
outlier detection using median absolute deviation. Sample-size and
MAD-zero gates suppress findings on near-uniform integer data. Lower the
threshold to flag more outliers.

```shell
fleetsweeper scan --all-contexts --db fleet.db --outlier-threshold 2.5
```

See [outliers](concepts/outliers.md) for the full statistical treatment.

## Where to go next

- [The fleet is the policy](concepts/fleet-is-policy.md). The design idea
  behind norm-based detection.
- [Server mode](operator/server-mode.md). Run as a service with dashboard and API.
- [ClusterScan CRD](operator/clusterscan.md). Full spec reference.
- [RBAC and API keys](operator/rbac.md). Multi-tenant access control.
