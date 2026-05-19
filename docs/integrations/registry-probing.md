# Private registry probing

The `image-audit` scanner can resolve container image manifests against
their registries when `--probe-registries` is enabled. Authentication
honours pod `imagePullSecrets` and the namespace's default ServiceAccount
secrets, so private registries with `kubernetes.io/dockerconfigjson` Secrets
work out of the box.

## Enable

```shell
fleetsweeper scan --all-contexts --probe-registries
# or, on a running server:
fleetsweeper serve --probe-registries
```

Helm:

```yaml
extraArgs:
  - --probe-registries
```

(For now this is passed via extraArgs; a top-level value will follow.)

## What probing adds

The `image-audit` scanner's `Data` payload gains four fields:

| Field | Meaning |
| --- | --- |
| `images_probed` | Unique images whose manifest resolved successfully. |
| `images_failed` | Unique images that errored (auth, network, missing). |
| `oldest_image_age_days` | Days since the oldest successfully-probed image's registry-reported creation. |
| `avg_image_age_days` | Mean age across all probed images. |

These flow into the standard report so trends, outliers, and the dashboard
all see image age automatically.

## Auth resolution

For each unique image, the scanner walks credentials in this order:

1. The pod's `spec.imagePullSecrets` (intersected with namespace Secrets).
2. The pod's ServiceAccount's `imagePullSecrets`.
3. The default ServiceAccount in the same namespace.
4. `go-containerregistry`'s default keychain (`$DOCKER_CONFIG`,
   `$HOME/.docker/config.json`, ECR, GCR, ACR, GHCR helpers).

The first credential whose `auths` key matches the image's registry host
wins. Anonymous fallback handles public images.

## Cache

Probe results are cached in-process for 5 minutes keyed by canonical image
reference. Two pods running the same image only round-trip the registry
once, even across cluster scans. The cache is best-effort and lost on
restart.

## Cost

Probing adds one HTTPS HEAD plus one config-blob GET per unique image, per
cache window. A 500-pod, 200-unique-image fleet probes once per scan cycle
and the cache absorbs the rest. Disable for low-egress or cost-sensitive
deployments.

## Failure modes

- **401/403**: missing or wrong credentials. The image's count moves into
  `images_failed`; the scan continues.
- **Network timeout**: counted as failed.
- **Image not found**: counted as failed.

Failures are intentionally silent at the scanner level so a private
registry outage cannot disrupt the rest of the fleet sweep. Operators who
want loud alerts on probe failures can watch the
`fleetsweeper_findings_total{scanner="image-audit"}` metric.
