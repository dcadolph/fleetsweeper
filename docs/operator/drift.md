# Local drift audit (`fleetsweeper drift`)

`fleetsweeper drift` is the command-line counterpart of the validating
admission webhook. It connects to a kubeconfig context, lists every
pod (or just one namespace), and applies the same baseline checks the
webhook would. It exits cleanly when the fleet norm is satisfied and
emits a per-pod report when it isn't.

Use it when:

- You want the admission protection without installing the webhook
  in-cluster (clusters with privileged-access restrictions, ephemeral
  CI clusters, vendor-managed control planes).
- You want a pre-flight gate in GitHub Actions: build the manifest,
  apply to a staging cluster, then run `fleetsweeper drift
  --fail-on-drift` before promoting to prod.
- You want to dry-run a manifest set against a pinned baseline
  before flipping the webhook from advisory to enforce.

## Baseline source

The drift command needs a baseline to compare against. Two sources:

```bash
# Derive from the most recent stored scan
fleetsweeper drift --db=/var/lib/fleetsweeper/data.db --context=prod-east

# Compare against a pinned YAML (produced by `fleetsweeper baseline export`)
fleetsweeper drift --baseline=./baseline/fleet.yaml --context=prod-east
```

Pinning the baseline is the recommended path for CI — it removes the
"which scan am I comparing against today" variability.

## Examples

```bash
# Single-namespace audit, human-readable
fleetsweeper drift --context=prod-east --namespace=payments \
  --baseline=./baseline/fleet.yaml

# Whole-cluster audit, JSON output for further processing
fleetsweeper drift --context=prod-east --baseline=./baseline/fleet.yaml --json

# CI gate: non-zero exit when any pod drifts
fleetsweeper drift --context=staging --baseline=./baseline/fleet.yaml \
  --fail-on-drift
```

Sample output:

```
Context:        prod-east
Pods inspected: 142
Pods drifted:   3
Source scan:    01J3ABCD...

[payments/checkout-7d-2k8sx]
  warn: container "checkout" image "ghcr.io/acme/checkout:v1.42" is not digest-pinned; fleet norm pins 91% of containers
  warn: pod runs under the default ServiceAccount; fleet norm uses named SAs for 86% of pods

[telemetry/agent-2k]
  warn: container "agent" has no security context; fleet norm runs 82% of containers as non-root

[ops/legacy-cron-abc]
  warn: container "runner" rootfs is writable; fleet norm has read-only rootfs on 78% of containers
```

## Compared to the webhook

| | Webhook | `fleetsweeper drift` |
| --- | --- | --- |
| Trigger | Every pod CREATE/UPDATE | Manual / CI |
| Scope | One pod per call | Whole context / namespace |
| Output | AdmissionResponse warnings | Local text or JSON |
| Failure | Allow + warn (advisory) or deny (enforce) | Exit 0 (info) or non-zero (`--fail-on-drift`) |
| In-cluster install | Required | Not required |

Both pipelines consume the same `internal/admission` checks, so a pod
that the CLI flags will be flagged identically by the webhook once
deployed.
