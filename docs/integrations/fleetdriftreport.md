# FleetDriftReport

`FleetDriftReport` is fleetsweeper's own CRD for emitting scan results into
the cluster as Kubernetes resources. Use this when you want fleetsweeper
findings to flow through your GitOps controller (Argo CD, Flux) and be
visible via `kubectl`.

## Enable

```yaml
serve:
  args:
    - --fleetdrift-output=/data/fleetdrift
```

After each scan the directory contains one `FleetDriftReport` YAML per
cluster plus a fleet-level summary. Apply them with your GitOps controller
or `kubectl apply -f /data/fleetdrift/`.

## Spec

```yaml
apiVersion: fleetsweeper.io/v1alpha1
kind: FleetDriftReport
metadata:
  name: prod-east
  namespace: fleetsweeper
spec:
  cluster: prod-east
  scanId: 1715961234567-deadbeef...
  scanTime: "2026-05-17T12:00:00Z"
  fleetScore:
    score: 88
    grade: B
status:
  observedAt: "2026-05-17T12:00:01Z"
  summary:
    critical: 2
    warning: 14
    info: 8
  findings:
    - severity: critical
      scanner: rbac
      title: ClusterRole grants pods/exec across all namespaces
      affected:
        - rolebinding/dev-team
      remediation:
        command: |
          kubectl delete clusterrolebinding dev-team-shell
        runbookURL: https://runbooks.example.com/rbac/exec
```

## Why use it

- `kubectl get fleetdriftreports` works.
- GitOps controllers can act on findings (open PRs, send pages, etc.).
- The `additionalPrinterColumns` show Score, Grade, Critical, Warning,
  and Age at a glance.

## Versus PolicyReport

| | FleetDriftReport | PolicyReport |
| --- | --- | --- |
| Spec ownership | Fleetsweeper (`fleetsweeper.io`) | CNCF WG (`wgpolicyk8s.io`) |
| Aimed at | GitOps controllers, operator tooling | Posture aggregation dashboards |
| Use both | Yes; they emit in parallel from the same scan |

Most operators turn on both. They are non-overlapping integrations.
