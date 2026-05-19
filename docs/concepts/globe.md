# Globe View

The dashboard ships a 3D fleet globe at `#/globe`. Each cluster is
rendered as a point colored by health status (healthy, busy, degraded,
critical). Critical clusters pulse red and the camera focuses on them
after load so a status TV draws the eye to trouble first. Click a point
to drill into the cluster detail page.

## Location resolution

Cluster locations are resolved in this order, highest priority first.

1. **Manual override in the fleetsweeper database**. Set via CLI or REST. Best when you do not control the target cluster's manifests.
2. **In-cluster ConfigMap `kube-system/fleetsweeper`**. Best when you do control the cluster. Lives with the cluster, GitOps-friendly, travels with kustomize, Helm, or Argo.
3. **In-cluster namespace annotations** on `kube-system`. Same idea as the ConfigMap, useful when your provisioning already patches the namespace.
4. **Auto-detect from cloud-region node labels**. The default fallback. The `geo` scanner reads `topology.kubernetes.io/region` on every node and maps known AWS, GCP, Azure, DigitalOcean, OCI, IBM, and Alibaba regions to approximate centroids. Zero configuration for managed clusters.

## CLI override

```
fleetsweeper location set store-nyc-42 \
  --lat 40.7589 --lng -73.9851 \
  --site "Store #42, Times Square" \
  --db fleet.db
fleetsweeper location list --db fleet.db
fleetsweeper location delete store-nyc-42 --db fleet.db
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
  site: "Store #42, Times Square"
  notes: "Flagship retail location."
```

Apply with `kubectl --context <cluster> apply -f deploy/examples/location-configmap.yaml`.
Fleetsweeper reads this on every scan. Updates take effect on the next
scan.

## In-cluster override via namespace annotations

```
kubectl --context <cluster> annotate namespace kube-system \
  fleetsweeper.io/lat=40.7589 \
  fleetsweeper.io/lng=-73.9851 \
  fleetsweeper.io/site="Store #42, Times Square" \
  --overwrite
```

The globe surfaces which source each placement came from so operators can
see whether a cluster is showing its auto-detected region, an in-cluster
override, or a database override.

## API endpoints

```
GET    /api/geo                       Cluster placements + health for the latest scan
GET    /api/locations                 List all manual overrides
PUT    /api/locations/{cluster}       Upsert a manual override (auth required)
DELETE /api/locations/{cluster}       Delete a manual override (auth required)
```
