# PolicyReport ingest

Fleetsweeper emits PolicyReports (see
[PolicyReport](policyreport.md)) so external dashboards can consume
its findings in the wgpolicyk8s.io schema. The `policy-reports`
scanner closes the loop in the other direction: it reads
`wgpolicyk8s.io/v1alpha2 PolicyReport` and `ClusterPolicyReport`
resources produced by every other policy tool in the cluster and
folds them into the Fleetsweeper findings stream.

A single dashboard can then summarise every policy tool's verdict on
the fleet:

- **Kyverno**. Its `PolicyReport` results land under `source=kyverno`.
- **Gatekeeper**. When configured with the
  `gatekeeper-policy-manager` PolicyReport publisher, results land
  under `source=gatekeeper`.
- **Trivy**. `aquasecurity.github.io` and `wgpolicyk8s.io` reports
  are both supported (the existing Trivy scanner reads the former,
  this scanner picks up the latter when Trivy is configured to emit
  PolicyReports).
- **kube-bench**. When run with a PolicyReport publisher,
  benchmarks roll up under `source=kubebench`.
- Anything else that publishes wgpolicyk8s.io PolicyReports. The
  scanner is source-agnostic.

## What's emitted

The scanner's data payload looks like:

```json
{
  "available": true,
  "reports": 7,
  "cluster_reports": 1,
  "total_fail": 22,
  "total_warn": 14,
  "total_error": 0,
  "by_source": [
    {"source": "kyverno",    "pass": 540, "fail": 14, "warn": 6,  "error": 0, "skip": 0},
    {"source": "gatekeeper", "pass":   8, "fail":  5, "warn": 0,  "error": 0, "skip": 0},
    {"source": "trivy",      "pass":   0, "fail":  3, "warn": 8,  "error": 0, "skip": 0}
  ],
  "top_failures": [
    {"source": "kyverno", "policy": "require-labels",    "rule": "check-labels",  "fail": 7, "severity": "high"},
    {"source": "kyverno", "policy": "require-limits",    "rule": "check-resources","fail": 5, "severity": "medium"},
    {"source": "gatekeeper", "policy": "k8spsphostnetwork", "fail": 3, "severity": "critical"}
  ]
}
```

`by_source` is sorted with the worst tool first; `top_failures` is
sorted by fail count descending so the dashboard can show the policies
firing most often without further client-side ranking.

## When the scanner short-circuits

If neither `PolicyReport` nor `ClusterPolicyReport` CRDs are
registered, the scanner returns `available=false` and zero counts.
Consumers can use that flag to distinguish "no policy tooling in
this cluster" from "policy tooling installed and clean."

If the CRDs are registered but the service account can't read them,
the scanner reports `available=true` with zero counts. The missing
permission is a configuration issue worth surfacing rather than
silently failing.

## RBAC

The scanner needs cluster-wide list permission on both CRDs:

```yaml
- apiGroups: ["wgpolicyk8s.io"]
  resources: ["policyreports", "clusterpolicyreports"]
  verbs: ["get", "list", "watch"]
```

The Helm chart's ClusterRole template adds these verbs automatically.
