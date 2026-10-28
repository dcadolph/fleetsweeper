# Findings and Remediation

Fleetsweeper translates raw scan data into actionable findings. Each
finding includes:

- A severity level (critical, warning, info).
- A rule naming the check that produced it, e.g. `workload-security/privileged`.
- The specific affected resources (named nodes, pods, bindings, images).
- A plain English description.
- A parameterized `kubectl` command using the affected resource names, when applicable.
- Embedded YAML manifests for "no NetworkPolicy" and "no ResourceQuota" findings.

## Rules and fingerprints

Every finding carries a `rule` of the form `<scanner>/<slug>`. The rule names
the check, never the cluster or a count, so the same check on two clusters
shares a rule. Fixed checks have fixed slugs (`node-health/not-ready`,
`certs/expiring-7d`). Checks derived from a scanner field put the field in the
slug: `security/outlier-enforced-count` for a fleet outlier,
`crds/cohort-outlier-crd-count` for a cohort outlier, `events/trend-warning-events`
and `events/self-drift-warning-events` for history.

A finding's `fingerprint` is the SHA-256 of its cluster, scanner, and rule
separated by NUL bytes. Titles may carry counts ("3 privileged containers"),
and a count change keeps the fingerprint, so:

- An acknowledgement placed at one count still covers the finding at the next.
- Persistence classes (chronic, intermittent, transient) follow the check
  across scans instead of restarting whenever a count moves.
- `fleetsweeper recommend` groups findings by scanner and rule, so leverage
  counts every cluster the same fix applies to.

The server includes `rule`, `fingerprint`, and `acked` on every finding it
serves. Ack a finding with `POST /api/findings/{fingerprint}/ack`.

## Norm remediations

A finding that a cluster deviates from the fleet or cohort norm carries a
remediation whose first line states the gap and whose second line inspects
the resources the field counts on that cluster:

```
# enforced_count is 4 here, 8 below the fleet median of 12
kubectl --context edge-nyc-42 get namespaces -L pod-security.kubernetes.io/enforce
```

## Norm provenance

Every fleet-relative finding (fleet outlier, cohort outlier, set outlier)
carries a `norm` object stating what it was measured against, so a reader can
check the claim without rerunning the statistics. Absolute-rule findings such
as `node-health/not-ready` carry no `norm`. That is how the two classes are
told apart.

| Field            | Meaning                                                                                        |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `scope`          | `fleet`, or the name of the cohort the norm was computed over.                                 |
| `kind`           | `numeric`, `string`, or `set`.                                                                 |
| `median`, `mad`  | Population median and median absolute deviation of a numeric field.                            |
| `z`              | This cluster's signed modified z-score, `0.6745 * (value - median) / mad`.                     |
| `mode`           | Most common value of a string field, held by `mode_share` of the population.                   |
| `consensus`      | Set members present in at least `threshold` of the population.                                 |
| `missing`        | The consensus members this cluster lacks.                                                      |
| `sample_size`    | Number of clusters in the population.                                                          |
| `threshold`      | Cutoff applied: modified z-score (numeric), minimum mode share (string), presence share (set). |
| `value`          | This cluster's value for the field.                                                            |
| `limited_sample` | True when the population was too small for MAD.                                                |

```json
"norm": {
  "scope": "fleet", "kind": "numeric", "median": 12, "mad": 1.5,
  "sample_size": 26, "threshold": 3.5, "value": "30", "z": 8.09,
  "limited_sample": false
}
```

Outliers served by `GET /api/outliers` carry the same fields inline. The
brief quotes the norm behind the most severe fleet-relative finding, e.g.
"Largest deviation: edge-nyc-42 enforced_count is 30 vs a fleet median of 12
across 26 clusters."

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
- **Outliers on the better side** of a field with a worse direction (fewer
  privileged containers than the fleet, more enforced namespaces) are info.

## Where a field's meaning is declared

One registry declares what each scanner field means to the report: its
severity, which direction is worse, which other field it restates, the
absolute rule that counts it, whether it is tracked for trends, and, for set
fields, the object list it is derived from. The severity, trend, set
projection, and availability tables are built from it, and a test fails when
an entry names a scanner or field that does not exist, so a misspelled field
cannot silently fall back to info. A field the registry does not declare is
still measured and reported at info severity, because a difference nobody
wrote a rule for is still worth seeing.

## Example findings

| Severity | Finding                                                       | Remediation                                                                                            |
| -------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Critical | `prod-eu` has 2 nodes under memory pressure                   | `kubectl --context prod-eu describe node n-12 n-17`                                                    |
| Warning  | Kubernetes version skew across fleet                          | `kubectl version`                                                                                      |
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
