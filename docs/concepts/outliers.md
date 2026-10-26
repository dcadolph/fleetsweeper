# Statistical outlier detection

Fleetsweeper compares every cluster against the rest of its population: the
whole fleet, and each cohort when clusters are tagged. Which detector runs
depends on how many clusters are in that population.

| Population&nbsp; | Detector                                         |
|------------------|--------------------------------------------------|
| 8 or more        | Modified z-score, mode share, and set consensus  |
| 3 to 7           | Leave-one-out majority diff, `limited_sample`    |
| 1 or 2           | None, and the report says why in `notes`         |

Scanner sections where every cluster reports the same data are skipped.

## Numeric fields: modified z-score

For continuous fields (CRD count, certificate days remaining, pod restart
count), fleetsweeper computes over the clusters that report the field:

- `median`. The population median.
- `MAD`. The median absolute deviation: the median of `|x_i - median|`.

A cluster is an outlier when its modified z-score exceeds the threshold:

```
|0.6745 * (x - median) / MAD| > 3.5
```

The constant 0.6745 scales the MAD so the score of a normal population
matches its ordinary z-score. The default threshold is 3.5, and the
`?threshold=` query parameter on `/api/outliers` overrides it. When the MAD
is zero (most clusters hold the exact same value) the field is skipped,
since any spread at all would score as infinite.

MAD is preferred over standard deviation because one badly misconfigured
cluster does not widen the band that is supposed to catch it.

## String fields: mode share

For categorical fields (PSA mode, ingress class, default storage class),
fleetsweeper finds the most common value. When that value holds at least 60%
of the clusters that report the field, every cluster with a different value
is an outlier. Below 60% the field is too fragmented to be a norm and nothing
is flagged.

## Set fields: consensus

For list fields, an item is part of the consensus when at least 60% of
clusters have it. A cluster missing any consensus item is an outlier, and
the finding names the consensus and the missing items.

## Small populations: the majority diff

Below 8 clusters the median and MAD of the whole population are unstable,
so a different rule runs for populations of 3 to 7. For each cluster `c`:

1. Take the other clusters, their median `m`, and their MAD `d`.
2. The others agree when every one of them is within `d` of `m`.
3. `c` stands apart when the others agree and its modified z-score against
   them, `0.6745 * (x - m) / d`, exceeds the threshold. When `d` is zero,
   any difference counts, and the score is reported as one million.

A finding is emitted only when exactly one cluster stands apart. Two
deviants in a population of five produce nothing, because there is no
majority to call either one wrong. For values 10, 12, and 30 the rule flags
30 alone: against 10 and 12 it scores 12.8, while 10 against 12 and 30
scores 0.82.

String fields follow the same shape: every other cluster holds one value
and `c` holds another. Set fields are not compared in small populations.

Every result of the majority diff carries `limited_sample: true` in its norm,
and its severity is capped at warning.

## Fewer than three clusters

With one or two clusters there is no basis for calling either one the
outlier. The report has no outliers and carries a line in `notes` instead:

```json
"notes": ["Fleet-relative outlier detection needs at least 3 clusters; this report has 2."]
```

Cohorts follow the same table. A cohort of 8 or more runs the full
detectors, a cohort of 3 to 7 runs the majority diff, and a smaller cohort
lists its members without outliers.
