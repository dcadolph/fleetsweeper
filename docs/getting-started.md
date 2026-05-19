# Getting Started

Five minutes to first scan.

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

## Where to go next

- [The fleet is the policy](concepts/fleet-is-policy.md). The design idea
  behind norm-based detection.
- [ClusterScan CRD](operator/clusterscan.md). Full spec reference.
- [RBAC and API keys](operator/rbac.md). Multi-tenant access control.
