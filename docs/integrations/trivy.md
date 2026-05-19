# Trivy Operator integration

Fleetsweeper consumes `VulnerabilityReport` custom resources produced by
[the Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
and turns them into fleet-wide drift signals. A cluster with 3x the
critical CVE count of the fleet median lights up as an outlier without
any per-cluster rule configuration.

## Requirements

- Install the Trivy Operator in each cluster you want vulnerability data
  for. The Helm chart at `aqua/trivy-operator` is the standard route.
- No Fleetsweeper-side configuration is needed; the scanner is registered
  by default and silently reports `available=false` for clusters where the
  CRD isn't installed.

## What the scanner reads

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  name: replicaset-frontend-7d4f
  namespace: app
  labels:
    trivy-operator.resource.name: frontend
    trivy-operator.container.name: app
report:
  artifact:
    repository: ghcr.io/example/frontend
    tag: "1.2.0"
  summary:
    criticalCount: 2
    highCount: 7
    mediumCount: 11
    lowCount: 3
```

The scanner aggregates `criticalCount`, `highCount`, `mediumCount`,
`lowCount`, and (where present) `unknownCount` across every report in the
cluster.

## Output

The `vulnerabilities` scanner emits the following Data block per cluster:

| Field | Meaning |
| --- | --- |
| `available` | `true` when the Trivy CRD is reachable. |
| `reports` | Number of VulnerabilityReport CRs seen. |
| `critical`, `high`, `medium`, `low`, `unknown` | Aggregate severity counts. |
| `top_images` | Worst-20 contributors by total finding count (critical breaks ties). |

These flow into the standard report pipeline, so MAD outlier detection
and forecasting work against vulnerability totals automatically.

## Per-image attribution

Each `VulnerableImage` entry in `top_images` carries:

- `namespace`
- `workload` (from the Trivy `trivy-operator.resource.name` label)
- `image` (registry/repository:tag from the `report.artifact` block)
- Per-severity counts

Use this to point remediation work at the highest-leverage targets.

## Mixed installs

When the Trivy Operator is installed in some clusters but not others, the
fleet baseline is still meaningful: the clusters without coverage report
zero counts and are excluded from the outlier statistic via the
`available=false` flag. Findings reflect the population of *covered*
clusters.

## Where Trivy ends and Fleetsweeper begins

- **Trivy Operator**: scans every image in the cluster on a schedule,
  emits per-pod VulnerabilityReports.
- **Fleetsweeper vulnerabilities scanner**: reads those reports, computes
  fleet aggregates, surfaces outliers and trends.

The two tools are complementary; install both.
