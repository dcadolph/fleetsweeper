# Globe View

The dashboard ships a 3D fleet globe at `#/globe`, and a smaller one on the
dashboard. Each cluster is a point:

- **Color** is its status (healthy, busy, degraded, critical).
- **Size** grows with its deviation mass, how far it sits from its norm
  across every field. See [Distributions](distributions.md).
- **Rings** pulse from clusters that some field flags, in the cluster's
  status color, spaced closer the more fields flag it.

The camera turns to the worst cluster after load, the side panel lists
clusters furthest from the norm first, and clicking a point opens its
detail.

## Location resolution

Cluster locations are resolved in this order, highest priority first.

1. **Manual override in the fleetsweeper database**. Set via CLI or REST. Best when you do not control the target cluster's manifests.
2. **In-cluster ConfigMap `kube-system/fleetsweeper`**. Best when you do control the cluster. Lives with the cluster, GitOps-friendly, travels with kustomize, Helm, or Argo.
3. **In-cluster namespace annotations** on `kube-system`. Same idea as the ConfigMap, useful when your provisioning already patches the namespace.
4. **Auto-detect from cloud-region node labels**. The default fallback. The `geo` scanner reads `topology.kubernetes.io/region` on every node and maps known AWS, GCP, Azure, DigitalOcean, OCI, IBM, and Alibaba regions to approximate centroids. Zero configuration for managed clusters.

## CLI override

```
fleetsweeper location set edge-nyc-42 \
  --lat 40.7589 --lng -73.9851 \
  --site "NYC edge 42" \
  --db fleet.db
fleetsweeper location list --db fleet.db
fleetsweeper location delete edge-nyc-42 --db fleet.db
```

## In-cluster override via ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fleetsweeper
  namespace: kube-system
data:
  lat: "40.7589"
  lng: "-73.9851"
  site: "NYC edge 42"
  notes: "Edge site."
```

Apply with `kubectl --context <cluster> apply -f deploy/examples/location-configmap.yaml`.
Fleetsweeper reads this on every scan. Updates take effect on the next
scan.

## In-cluster override via namespace annotations

```
kubectl --context <cluster> annotate namespace kube-system \
  fleetsweeper.io/lat=40.7589 \
  fleetsweeper.io/lng=-73.9851 \
  fleetsweeper.io/site="NYC edge 42" \
  --overwrite
```

The globe surfaces which source each placement came from so operators can
see whether a cluster is showing its auto-detected region, an in-cluster
override, or a database override.

## API endpoints

```
GET    /api/geo                       Placements, status, deviation mass, and flagged fields for the latest scan
GET    /api/locations                 List all manual overrides
PUT    /api/locations/{cluster}       Upsert a manual override (auth required)
DELETE /api/locations/{cluster}       Delete a manual override (auth required)
```
