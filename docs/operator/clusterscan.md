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
| `nextScanTime` | RFC3339 timestamp of the next planned scan. |
| `observedScore` | Fleet score (0-100) from the most recent scan. |
| `observedGrade` | Letter grade (A-F) from the most recent scan. |
| `observedCritical` | Critical finding count. |
| `observedWarning` | Warning finding count. |
| `observedClusters` | Number of clusters that produced data in the scan. |
| `message` | Short human-readable status summary. |

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
NAME         INTERVAL  PHASE       SCORE  GRADE  CRITICAL  LASTSCAN   AGE
prod-fleet   30m       Succeeded   88     B      2         12s        2m
```

## Lifecycle and edge cases

- **Interval change**: takes effect on the next reconcile pass. The next scan
  is scheduled relative to the last completed scan time, so shortening an
  interval can immediately make a scan due.
- **In-flight scan when controller restarts**: the controller does not see
  the in-flight state across restarts. The next reconcile pass evaluates
  whether the interval has elapsed and may trigger a new scan immediately.
  Scans are idempotent in storage (each gets a fresh ID).
- **Resource deletion mid-scan**: the in-flight scan completes and its
  results are persisted; the status patch fails silently (the resource is
  gone) and is logged at warn level.
- **Group with no members**: the controller marks the scan `Failed` with a
  descriptive message.
