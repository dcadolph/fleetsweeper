# Leader election

When more than one fleetsweeper replica runs against a shared backend, only
one of them should fire side effects (scheduled scans, controller
reconciliation, outbound webhook dispatch). Leader election via
`coordination.k8s.io/v1` Lease objects coordinates this automatically.

## Enable

Leader election runs only when the pod has a service-account token and a
namespace for the Lease, set with `--leader-namespace` or the
`$POD_NAMESPACE` environment variable. Otherwise election is skipped and
every replica runs the scheduler and controller.

```yaml
leaderElection:
  enabled: true
  name: ""    # defaults to the release name
```

## How it works

- The configured ServiceAccount holds a `coordination.k8s.io/v1` Lease in
  the deployment namespace named `<release>` (or the value of
  `leaderElection.name`).
- One replica acquires the lease at startup; the rest wait.
- The leader renews every 5 seconds within a 30-second lease duration.
- If the leader dies or fails to renew within 20 seconds, another replica
  acquires the lease and starts side effects.
- The HTTP API runs on every replica regardless of leadership, so the load
  balancer can fan out reads and writes across pods. Only periodic / side-
  effect-producing goroutines are gated by leadership.

## Behavior without leader election

When `leaderElection.enabled=false` or the process is running outside a
cluster, every replica starts the scheduler and controller independently.
This is fine with a single replica; with multiple replicas it produces
duplicate scans and double webhook deliveries. The default keeps this from
happening by accident.

## Required permissions

The chart's namespaced Role grants the ServiceAccount these verbs on
Lease objects in the deployment namespace:

```yaml
- apiGroups: ["coordination.k8s.io"]
  resources: [leases]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: [events]
  verbs: ["create", "patch"]
```

Events are written by the leaderelection library for transition diagnostics
and are visible with `kubectl describe lease <release>`.

## Tunables

The defaults are a 30s lease, a 20s renew deadline, and a 5s retry period.
They are fixed and not exposed as flags. File an issue if your deployment
needs different values.
