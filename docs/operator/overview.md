# Operator Overview

Fleetsweeper ships with a controller that turns the API into declarative
Kubernetes resources. You write `ClusterScan` objects; the controller
schedules scans, writes status back, and emits artefacts.

## Architecture

```
+--------------------+        +---------------------+
| kubectl apply -f   |  --->  | ClusterScan CR      |
| clusterscan.yaml   |        | (fleetsweeper.io)   |
+--------------------+        +-----------+---------+
                                          |
                                          | watched by
                                          v
+-------------------------------------------------+
| fleetsweeper serve --controller                 |
|                                                 |
|   Reconciler --> ScanRunner --> scanners        |
|       ^                |                        |
|       | status patch   v                        |
|       +-------- store + emit (PR, Slack, ...)   |
+-------------------------------------------------+
```

One process runs both the HTTP API and the controller. The controller polls
the API server every `--controller-poll` (default 15s), lists all
`ClusterScan` resources in the configured namespace scope, and triggers a
scan for any resource whose `interval` has elapsed since `status.lastScanTime`.

Concurrency is bounded by both the per-resource in-flight set and the
global scan mutex, so a slow scan never causes a stampede.

## Enabling the controller

In-cluster (via Helm):

```yaml
controller:
  enabled: true
  namespace: ""        # empty watches all namespaces
  pollInterval: 15s
crds:
  install: true        # ships ClusterScan + FleetDriftReport CRDs
```

Outside the cluster:

```shell
fleetsweeper serve \
  --db /data/fleet.db \
  --controller \
  --controller-context home-cluster \
  --controller-namespace fleetsweeper
```

## What the controller writes back

| Field | When set |
| --- | --- |
| `status.phase` | Always (`Pending`, `Running`, `Succeeded`, `Failed`, `Paused`). |
| `status.lastScanID` | After a scan completes successfully. |
| `status.lastScanTime` | After a scan completes successfully. |
| `status.nextScanTime` | After every reconcile pass. |
| `status.observedScore` | After a scan completes successfully. |
| `status.observedGrade` | After a scan completes successfully. |
| `status.observedCritical` | After a scan completes successfully. |
| `status.observedWarning` | After a scan completes successfully. |
| `status.observedClusters` | After a scan completes successfully. |
| `status.message` | Always; short human-readable summary. |

## Pause and resume

Set `spec.paused: true` to suspend reconciliation. The controller writes
`phase: Paused` and stops triggering scans until the field is removed or
set back to `false`. Useful during incident response when you do not want
fleetsweeper traffic touching the API server.

## See also

- [ClusterScan CRD reference](clusterscan.md)
- [Helm chart values](helm.md)
- [RBAC and API keys](rbac.md)
