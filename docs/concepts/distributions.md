# Distributions

Every field the outlier detectors measure has a distribution: each cluster's
value, the norm, and how far each cluster sits from it. The dashboard draws
them as strips, the deviation matrix, and the history charts, and
`GET /api/distributions` serves them.

## What a strip shows

A strip is one field across one population. Each cluster is a dot on a shared
axis.

- The vertical line is the median.
- The shaded band is where a value may sit before it is flagged. Its half
  width is `3.5 * MAD / 0.6745`, the distance at which the modified z-score
  reaches the threshold, so a dot outside the band is an outlier.
- Red dots are outliers that raise a finding.
- Hollow dots are fleet outliers that their tagged cohort holds within the
  cohort's own norm. They raise no finding. See [cohorts](fleet-is-policy.md#cohorts-the-fleet-is-several-populations).
- A ringed dot is the cluster the page is about.

When the MAD is zero, because most clusters hold the exact same value, the
strip draws the dots and the median with no band, and nothing is flagged.

String fields have no axis. Their strip names the most common value, the
share of clusters holding it, and the clusters that differ. Set fields name
how many consensus members most clusters have, and the clusters missing some.

A strip marked `limited sample` comes from a population of 3 to 7, where the
leave-one-out majority diff runs instead of the median and MAD of the whole
population. See [Outliers](outliers.md).

## Fleet and cohort scope

Each field has a fleet distribution, over every cluster, and one per cohort
with enough members. The Outliers page and the dashboard switch between them.
A cluster in a tagged cohort answers to its cohort's norm, so the cohort
strip is the one that decides whether it raises a finding.

## Deviation mass

Deviation mass is how far a cluster sits from its norm across every field:
the sum over the fleet distributions of the cluster's `|z|`, each capped at 10
so one extreme field cannot drown the rest. For a cluster in a tagged cohort,
each field's z comes from the cohort's distribution where the cohort has one.
The dashboard ranks clusters by it, the drift ledger tracks how it moves
between scans, and the globe sizes markers by it.

## The deviation matrix

The deviation matrix is every cluster against every field, colored by `|z|`,
with rows in the order of the cohort map so a cohort that drifts together
shows as a block. Clicking a cell opens that field's strip with the cluster
ringed.

## API

- `GET /api/distributions` serves one scan's distributions, fleet scope by
  default. `?scope=` picks a cohort or `*` for every scope, and `?scanner=` and
  `?field=` filter.
- `GET /api/distributions/history?scanner=&field=` serves one field's
  distribution over recent scans, oldest first.
- `GET /api/drift` serves the drift ledger. See
  [What changed](../operator/whatchanged.md).
