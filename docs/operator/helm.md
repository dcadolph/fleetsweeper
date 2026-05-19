# Helm chart

```shell
helm install fleetsweeper deploy/helm/fleetsweeper \
  --namespace fleetsweeper --create-namespace \
  --set auth.token=$(openssl rand -hex 32) \
  --set controller.enabled=true
```

## Key values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/dcadolph/fleetsweeper` | Container image. |
| `image.tag` | `""` (chart appVersion) | Override to pin a release. |
| `replicaCount` | `1` | Number of pods. Multi-replica is not yet HA-safe (single-writer SQLite). |
| `auth.token` | `""` | Bootstrap bearer token. Empty + `auth.insecure=false` yields 403 on writes. |
| `auth.insecure` | `false` | Disables auth entirely. Private networks only. |
| `cors.origins` | `[]` | CORS allowlist. Empty refuses cross-origin requests. |
| `scheduler.interval` | `""` | Auto-scan interval (e.g. `30m`). Empty disables. |
| `scheduler.allContexts` | `true` | Use every kubeconfig context for scheduled scans. |
| `persistence.enabled` | `true` | PVC for `/data/fleet.db`. |
| `persistence.size` | `5Gi` | Disk size. |
| `rbac.create` | `true` | Install least-privilege ClusterRole + binding. |
| `crds.install` | `true` | Install ClusterScan and FleetDriftReport CRDs. |
| `controller.enabled` | `false` | Run the ClusterScan reconciler. |
| `controller.namespace` | `""` | Restrict the controller to one namespace. |
| `controller.pollInterval` | `15s` | How often the reconciler re-evaluates. |

## CRD lifecycle

`crds.install` defaults to `true` so an out-of-the-box `helm install` is
self-contained. In multi-tenant or GitOps environments where CRDs are
managed separately, set it to `false` and apply the CRDs from
`deploy/crds/` independently.

## Running outside Kubernetes

The chart targets in-cluster runs. For local or non-Kubernetes deployments
use the binary directly:

```shell
fleetsweeper serve \
  --db /var/lib/fleetsweeper/fleet.db \
  --auth-token "$FLEETSWEEPER_AUTH_TOKEN" \
  --addr :8080 \
  --admin-addr 127.0.0.1:8081
```
