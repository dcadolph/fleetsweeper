# Findings and Remediation

Fleetsweeper translates raw scan data into actionable findings. Each
finding includes:

- A severity level (critical, warning, info).
- The specific affected resources (named nodes, pods, bindings, images).
- A plain English description.
- A parameterized `kubectl` command using the affected resource names, when applicable.
- Embedded YAML manifests for "no NetworkPolicy" and "no ResourceQuota" findings.

## Severity calibration

Severity is conservative on purpose. The goal is for a critical finding to
be worth an SRE's attention, not a daily false positive.

- **Kubernetes version differences** are info for patch-only skew, warning
  for a single minor, critical only when skew exceeds one minor (outside
  the upstream skew policy).
- **ClusterRoleCount divergence** is warning, not critical, because cloud
  add-ons legitimately differ.
- **Maximum CPU and memory percentages** are warning, since natural
  per-cluster variation should not page an SRE.

## Example findings

| Severity | Finding                                                       | Remediation                                                                                            |
| -------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Critical | `prod-eu` has 2 nodes under memory pressure                   | `kubectl --context prod-eu describe node n-12 n-17`                                                    |
| Warning  | Kubernetes version skew across fleet                          | `kubectl version --short`                                                                              |
| Warning  | `prod-eu` has 7 warning events in the last hour               | `kubectl --context prod-eu get events --field-selector type=Warning`                                   |
| Warning  | `dev` has 5 namespaces without Pod Security enforcement       | `kubectl --context dev label namespace <ns> pod-security.kubernetes.io/enforce=baseline --overwrite`   |

## Recommendations

The recommend pipeline ranks findings by leverage. A fix that takes ten
clusters from drifted to clean ranks ahead of the same fix on one cluster.
See [`docs/operator/recommend.md`](../operator/recommend.md).

## Remediation pull requests

For findings that carry an inline YAML manifest, `fleetsweeper remediate`
opens a pull request against a GitOps repo via the GitHub REST API.
Default is dry-run. Pass `--push` and a token to actually create the PR.

```
fleetsweeper remediate \
  --db fleet.db --scan-id latest \
  --cluster prod-us-east-1 \
  --scanner network-policies \
  --github-repo myorg/gitops \
  --github-token "$GITHUB_TOKEN" \
  --push
```
