# ClusterScan CRD

`apiVersion: fleetsweeper.io/v1alpha1`, `kind: ClusterScan`, scope: `Namespaced`.

A ClusterScan declares one recurring scan: which clusters, how often, and
what to emit when it completes. The controller reconciles it on its declared
interval and writes the outcome back to `.status`.

## Spec

| Field | Type | Description |
| --- | --- | --- |
| `interval` | duration string | Required. Cadence between scans. Go duration format (`15m`, `1h`, `6h`). |
| `contexts` | string array | Kubeconfig context names to scan. Required when `group` is empty. |
| `group` | string | Fleetsweeper group name whose members will be scanned. Mutually exclusive with `contexts`. |
| `scanners` | string array | Optional allowlist of scanner names. Empty runs all registered scanners. |
| `emit.fleetDriftReport` | boolean | When true, emit `FleetDriftReport` CRs after each scan. |
| `emit.policyReport` | boolean | When true, emit wgpolicyk8s.io `PolicyReport` resources. |
| `emit.slack` | boolean | When true, deliver new critical findings to the configured Slack webhook. |
| `paused` | boolean | When true, the controller skips this resource. |

## Status

| Field | Description |
| --- | --- |
| `phase` | `Pending` / `Running` / `Succeeded` / `Failed` / `Paused`. |
| `lastScanID` | Identifier of the most recent successful scan. |
| `lastScanTime` | RFC3339 timestamp of the most recent successful scan. |
| `nextScanTime` | RFC3339 timestamp of the next planned scan, including a retry after a failure. |
| `observedScore` | Fleet score (0-100) from the most recent successful scan. |
| `observedGrade` | Letter grade (A-F) from the most recent successful scan. |
| `observedCritical` | Critical finding count. Written as `0` when it drops to zero. |
| `observedWarning` | Warning finding count. Written as `0` when it drops to zero. |
| `observedClusters` | Number of clusters that produced data in the scan. |
| `observedGeneration` | The `metadata.generation` this status was computed from. |
| `consecutiveFailures` | Scans that failed since the last success. Reset to `0` on success. |
| `message` | Short human-readable status summary. |
| `conditions` | `Ready`, `Scanning`, and `Failed`. See below. |

Every status write sets every field above, so a count that falls to zero is
recorded rather than left at its previous value. Writes are guarded by the
resource's `resourceVersion`, so a write computed from an out-of-date copy is
rejected and retried instead of overwriting newer status.

### Conditions

| Type | True when | Reasons |
| --- | --- | --- |
| `Ready` | The most recent scan succeeded. | `ScanSucceeded`, `ScanFailed`, `InvalidSpec`, `Paused` |
| `Scanning` | A scan is running now. | `ScanStarted`, then the outcome's reason |
| `Failed` | The most recent scan failed or the spec is invalid. | `ScanFailed`, `InvalidSpec`, `ScanSucceeded`, `Paused` |

Each condition carries the `observedGeneration` it was written for and keeps
its `lastTransitionTime` until its status actually changes.

### Events

The controller records Events on the ClusterScan through the `events` API in
the core group (the chart and `deploy/rbac.yaml` grant `create` and `patch`):

| Type | Reason | When |
| --- | --- | --- |
| `Normal` | `ScanStarted` | A due scan begins. |
| `Normal` | `ScanSucceeded` | The scan completed. The message has the scan ID, score, grade, and counts. |
| `Warning` | `ScanFailed` | The scan returned an error. The message has the error. |
| `Warning` | `InvalidSpec` | The spec cannot be acted on, for example an unparseable interval. Emitted once per distinct problem. |

## Example

```yaml
apiVersion: fleetsweeper.io/v1alpha1
kind: ClusterScan
metadata:
  name: prod-fleet
  namespace: fleetsweeper
spec:
  interval: 30m
  contexts:
    - prod-east
    - prod-west
  emit:
    fleetDriftReport: true
    policyReport: true
    slack: true
```

After the first reconciliation:

```text
$ kubectl get clusterscan -n fleetsweeper
NAME         INTERVAL  PHASE       READY  SCORE  GRADE  CRITICAL  LASTSCAN   AGE
prod-fleet   30m       Succeeded   True   88     B      2         12s        2m
```

`kubectl describe clusterscan prod-fleet -n fleetsweeper` shows the
conditions and the Events together:

```text
Status:
  Conditions:
    Last Transition Time:  2026-10-25T18:02:11Z
    Message:               scan 01JB... completed: score 88 (B), 2 critical, 7 warning across 2 clusters
    Observed Generation:   1
    Reason:                ScanSucceeded
    Status:                True
    Type:                  Ready
    ...
  Consecutive Failures:    0
  Next Scan Time:          2026-10-25T18:32:11Z
  Observed Critical:       2
  Observed Generation:     1
  Phase:                   Succeeded
Events:
  Type    Reason         Age   From                     Message
  ----    ------         ----  ----                     -------
  Normal  ScanStarted    14s   fleetsweeper-controller  Scan started
  Normal  ScanSucceeded  12s   fleetsweeper-controller  scan 01JB... completed: score 88 (B), 2 critical, 7 warning across 2 clusters
```

## Lifecycle and edge cases

- **Scheduling**: a scan is due at `nextScanTime`. Besides the poll loop
  (`--controller-poll`), each reconcile schedules its resource for the moment
  its next scan is due.
- **Failed scan**: the scan is retried after one minute, then two, then four,
  doubling with each consecutive failure and never later than
  `spec.interval`. A failing scan is never re-run on every poll.
- **Interval change**: takes effect on the next reconcile pass. After a
  successful scan the next one is due at the last scan time plus the new
  interval, so shortening an interval can immediately make a scan due.
- **Status write failure**: the resource is requeued with exponential backoff,
  which resets after the next successful reconcile.
- **In-flight scan when controller restarts or loses leadership**: the scan is
  canceled with the controller. The next reconcile pass sees the past
  `nextScanTime` and runs it again. Scans are idempotent in storage (each gets
  a fresh ID).
- **Resource deletion mid-scan**: the controller cancels the running scan.
  Nothing further is written for the deleted resource.
- **Group with no members**: the controller marks the scan `Failed` with a
  descriptive message.
