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
| `scheduler.contexts` | `[]` | Contexts for scheduled scans. Empty scans every kubeconfig context. |
| `kubeconfig.existingSecret` | `""` | Secret holding the kubeconfig to scan with. Empty scans the host cluster only. |
| `kubeconfig.key` | `config` | Key in that Secret whose value is the kubeconfig file. |
| `persistence.enabled` | `true` | PVC for `/data/fleet.db`. |
| `persistence.size` | `5Gi` | Disk size. |
| `rbac.create` | `true` | Install least-privilege ClusterRole + binding. |
| `crds.install` | `true` | Install ClusterScan and FleetDriftReport CRDs. |
| `controller.enabled` | `false` | Run the ClusterScan reconciler. |
| `controller.namespace` | `""` | Restrict the controller to one namespace. |
| `controller.pollInterval` | `15s` | How often the reconciler re-evaluates. |

## Scanning a fleet

Without a kubeconfig the server sees one cluster: the one it runs in, reached
through the release's ServiceAccount and named `in-cluster` in reports. To
scan a fleet, store a kubeconfig in a Secret and point the chart at it:

```shell
kubectl --namespace fleetsweeper create secret generic fleet-kubeconfig \
  --from-file=config=$HOME/.kube/config
helm upgrade fleetsweeper deploy/helm/fleetsweeper --namespace fleetsweeper \
  --reuse-values --set kubeconfig.existingSecret=fleet-kubeconfig
```

The Secret is mounted read-only at `/var/run/fleetsweeper/kubeconfig` and
passed as `--kubeconfig`. Scheduled and triggered scans then read every context
in it. Each context needs read access on its own cluster, the same access the
chart's ClusterRole grants on the host. A kubeconfig whose users run an exec
plugin (`aws`, `gcloud`, `kubelogin`) needs that binary in the image, which the
distroless image does not carry, so use static tokens or client certificates
for in-cluster scans. The ClusterScan controller keeps using the
ServiceAccount for its own cluster unless `--controller-context` names a
context.

## CRD lifecycle

`crds.install` defaults to `true` so an out-of-the-box `helm install` is
self-contained. In shared or GitOps clusters where CRDs are
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
