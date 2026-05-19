# Statistical outlier detection

Fleetsweeper uses two outlier-detection strategies depending on the metric
type.

## Numeric metrics: MAD against the fleet median

For continuous metrics (CRD count, certificate days remaining, pod
restart rate), fleetsweeper computes:

- `median` — the fleet-wide median.
- `MAD` — the median absolute deviation: the median of `|x_i - median|`.

A cluster is an outlier when `|cluster_value - median| > threshold * MAD`.
The default threshold is 3.5; the `?threshold=` query parameter on
`/api/outliers` overrides it.

MAD is preferred over standard deviation because it is robust to outliers
in the input distribution — exactly the situation we are most interested
in. A fleet with one badly-misconfigured cluster does not have its
detection sensitivity degraded by that cluster's presence.

## Categorical metrics: mode-mass

For categorical metrics (PSA mode, ingress class name, default storage
class), fleetsweeper computes the modal value and reports the cluster set
that disagrees. A "mode-mass" of 70%+ is considered a meaningful baseline;
when the mode-mass is lower the metric is too fragmented to be a
trustworthy norm and is suppressed.

## Sample-size gating

For small fleets (under five clusters) the MAD can collapse to zero or
become unstable. Fleetsweeper marks findings from those fleets with a
`limited_sample` flag and computes an additional confidence interval the
UI can show alongside the result. The same flag drives whether trend
findings fire: a two-scan series is not enough to produce a regression
verdict.
