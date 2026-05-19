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

After every scan the directory contains one PolicyReport YAML per cluster
plus a fleet-level report. Point your GitOps tool at the directory.

## Resource shape

```yaml
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  name: prod-east-fleetsweeper
  namespace: fleetsweeper
results:
  - policy: fleetsweeper/image-audit
    rule: digest-pinning
    category: hygiene
    severity: warning
    result: fail
    source: fleetsweeper
    timestamp: { seconds: 1747488000 }
    properties:
      cluster: prod-east
      scanner: image-audit
      remediation: |
        kubectl set image deploy/foo container=image@sha256:abc123...
summary:
  pass: 14
  fail: 3
  warn: 1
  error: 0
  skip: 0
```

## Why use it

- Single-pane-of-glass dashboards (Policy Reporter UI) show all your
  posture findings together.
- Existing alerting on PolicyReport severity continues to fire for
  fleetsweeper outputs.
- GitOps consumption: PolicyReport is a Kubernetes-native resource.
