# Fleet Score

The Fleet Score is a single 0-100 number that summarizes fleet health from
the most recent scan. A letter grade (A-F) is rendered alongside for quick
recognition.

## How it is computed

The score starts at 100 and subtracts a cost for each kind of trouble,
floored at zero:

1. **Findings.** 6 points per critical finding (capped at 36), 1.5 per
   warning (capped at 24), 0.25 per info (capped at 5). The caps keep a
   single noisy category from collapsing the score on volume alone. One
   fact is charged once: a norm finding that restates another finding on
   the same cluster is dropped before the count (see
   [One fact, one finding](findings.md#one-fact-one-finding)).
2. **Unhealthy clusters.** Up to 20 points scaled by the fraction of
   clusters in critical status, plus up to 10 points scaled by the
   fraction in degraded or strained status. Scaling by fraction keeps the
   cost proportional: one critical cluster in a fleet of three costs more
   than one in a fleet of thirty. A cluster's status comes from its own
   findings only. A fleet-wide finding such as version skew costs its
   points once, through its own term, and marks no cluster.
3. **Version skew.** 10 points when Kubernetes minor versions across the
   fleet differ by two or more (critical skew), 3 points when they differ
   by exactly one (warning skew). Patch-only differences cost nothing
   here, and unparseable version strings are ignored.
4. **Worst node health.** Up to 10 points scaled by the unhealthy-node
   fraction of the single worst cluster. The worst cluster is used rather
   than the fleet average so one cluster melting down is not hidden by a
   healthy long tail.

The three largest costs are reported as the score's drivers, so the
number always arrives with its explanation. The full ledger, every term
with every rule and cluster it charged and what each cap forgave, is
`GET /api/score/attribution` and the dashboard's "How the score adds up".
The exact weights live in `internal/report/score.go` and are documented
inline.

## Coverage gate

A score is only graded when enough of the fleet was observed to back it.
Every report counts its scanner runs: one expected run per listed cluster
for every scanner that ran on at least one cluster. A run is observed when
it finished OK or found its feature not served (unavailable), partial when
it was degraded, and blind when it errored or never ran on that cluster.

The score is graded when both hold:

- Every listed cluster has at least one observed run.
- At least 80 percent of expected runs are observed. The floor is the
  constant `minCoverageFraction` in `internal/report/score.go`.

An ungraded score has `graded: false` and an empty `grade`. Its headline
leads with the gap and labels the number, for example "Not enough data: 6
of 6 scanner runs did not observe the fleet, and 2 of 2 clusters had no
complete scanner run. Observed-only score 100." The number is still
computed from what was observed, so it is there for inspection, but it is
not the fleet's health. The brief leads with the same sentence.

A graded score with blind or partial runs names them after the band, and
its top band reads "nothing flagged in what was observed" in place of "no
meaningful drift", because a blind run cannot vouch for anything. A fully
observed fleet reads exactly as before.

The counts travel in `coverage`: `expected_runs`, `observed_runs`,
`blind_runs`, `blind_clusters`, and `fraction` (observed over expected).

## Cluster score

Each cluster also gets a 0-100 score on the same scale. It charges the
cluster for its own findings at their severity, and for each fleet-scoped
finding that marks it, at the mark's severity. A fleet finding such as
version skew marks only the clusters off the majority, so only those pay.
A fleet finding that marks no cluster costs no cluster anything and counts
once in the Fleet Score. This is the same rule that sets cluster status, so
a cluster that reads healthy never loses points to a critical or warning
finding.

A cluster with any blind scanner run (errored, or never run on it) that no
finding made degraded or critical reads `unknown` instead of `healthy`. Its
cluster score pays the degraded status cost, and its headline reads
"Unknown. N scanner runs did not observe this cluster." The Fleet Score
does not charge unknown clusters. The coverage gate covers them instead.

## Provenance

A score never travels alone. Every surface that reports it (the report
JSON, the dashboard hero card, the brief, Slack notifications, export
metadata, and the Prometheus and OpenTelemetry metrics) also carries:

- `sample_size`: the clusters that contributed scanner data to the score.
- `dimensions`: the scan dimensions that contributed data from at least
  one cluster.
- `excluded_clusters`: scanned clusters that produced no usable data and
  were left out of the statistical population.
- `coverage`: the scanner runs behind the score and how many observed the
  fleet (see [Coverage gate](#coverage-gate)).

A score computed across six clusters and one computed across sixty are
different claims. The provenance says which one you are reading.

## What the score does not measure

The score measures deviation within your own fleet, nothing else. A fleet
that is uniformly misconfigured has no outliers and scores well, because
the baseline is the fleet, not an external standard. Pair Fleetsweeper
with a policy engine or benchmark scanner for absolute rules; the README
section "Consistency is not correctness" works through this in detail.

## Grade thresholds

| Grade | Range |
| --- | --- |
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

## Trends

The forecast at `/api/forecast/fleet-score` fits a least squares line
through the score history and projects one median scan interval ahead, the
time of the next scan at the usual cadence, with a 95% prediction interval
clamped to 0 to 100. It needs at least 4 scans; with fewer it says so
instead of guessing. `/api/forecast/clusters` does the same per cluster.
