# Fleetsweeper

> The fleet is the policy.

Fleetsweeper scans multiple Kubernetes clusters in parallel and flags drift —
not whether individual clusters violate a rulebook, but whether they have
diverged from each other. The baseline is derived from your own fleet, so
you do not write policies up front.

## What it does

- Scans every cluster across 22 dimensions (RBAC, images, versions, certs,
  network policies, security context, deprecated APIs, and more).
- Computes a 0-100 Fleet Score with a letter grade.
- Detects per-cluster outliers using median-absolute-deviation against the
  fleet median (no threshold tuning required).
- Forecasts whether the score is improving or regressing using OLS with
  t-statistic gating, so you only see significant trends.
- Emits the result as `FleetDriftReport` and standard wgpolicyk8s.io
  `PolicyReport` resources for GitOps consumption.
- Posts critical findings to Slack and triggers remediation PRs against a
  GitOps repo.

## What it is not

Fleetsweeper is **not** a replacement for [Polaris](https://polaris.docs.fairwinds.com/),
[Kubescape](https://kubescape.io/), or [kube-bench](https://github.com/aquasecurity/kube-bench).
Those tools check each cluster against a rulebook. Fleetsweeper finds drift
you forgot to write a rule for, by comparing clusters to each other.
Run both together.

## Three-line install

```shell
kubectl apply -f https://raw.githubusercontent.com/dcadolph/fleetsweeper/main/deploy/crds/clusterscan.yaml
helm install fleetsweeper deploy/helm/fleetsweeper --set controller.enabled=true
kubectl apply -f deploy/examples/clusterscan-prod.yaml
```

Then visit the dashboard at port 8080 of the fleetsweeper service.

## Where to go next

- [Getting Started](getting-started.md). First scan in five minutes.
- [Operator overview](operator/overview.md). Declarative scans with
  ClusterScan CRs and a reconciler.
- [RBAC and API keys](operator/rbac.md). Multi-tenant access control.
- [The fleet is the policy](concepts/fleet-is-policy.md). Why norm-based
  detection beats rule authoring at scale.
