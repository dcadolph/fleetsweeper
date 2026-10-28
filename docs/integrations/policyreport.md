# PolicyReport

Fleetsweeper emits findings as standard `wgpolicyk8s.io/v1alpha2`
`PolicyReport` resources. Kyverno, Trivy Operator, and Policy Reporter UI
already understand this format, so fleetsweeper's findings appear alongside
those tools' results without extra configuration.

## Enable

```yaml
serve:
  args:
    - --policy-report-output=/data/policyreports
    - --policy-report-namespace=fleetsweeper
```

After every scan the directory contains one PolicyReport YAML per cluster.
Fleet-wide findings appear in every cluster's report. Point your GitOps tool
at the directory.

## Resource shape

```yaml
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  name: fleetsweeper-prod-east
  namespace: fleetsweeper
  labels:
    app.kubernetes.io/managed-by: fleetsweeper
    fleetsweeper.io/cluster: prod-east
    fleetsweeper.io/scan-id: scan-1
    policy.kubernetes.io/engine: fleetsweeper
summary:
  pass: 0
  fail: 1
  warn: 0
  error: 0
  skip: 0
results:
  - source: fleetsweeper
    policy: image-audit
    rule: image-audit/digest-pinning
    category: Workloads
    severity: medium
    result: fail
    message: Image not pinned by digest
    timestamp: { seconds: 1747488000, nanos: 0 }
    properties:
      fleetsweeper.cluster: prod-east
      remediation.command: kubectl set image deploy/foo container=image@sha256:abc123
```

## Why use it

- Single-pane-of-glass dashboards (Policy Reporter UI) show all your
  posture findings together.
- Existing alerting on PolicyReport severity continues to fire for
  fleetsweeper outputs.
- GitOps consumption: PolicyReport is a Kubernetes-native resource.
