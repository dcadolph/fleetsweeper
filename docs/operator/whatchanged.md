# `fleetsweeper whatchanged`

After a deploy or an incident, the most useful question is rarely
"what does the fleet look like". It is "what changed since the last
scan." `whatchanged` answers that, comparing two scans and emitting only
the deltas: which clusters drifted against the fleet norm and why, which
findings are new or cleared, and how per-cluster scores moved.

## Usage

```bash
# Compare the latest two scans
fleetsweeper whatchanged --db=/var/lib/fleetsweeper/data.db

# Compare specific scans (order: older first)
fleetsweeper whatchanged 01J3ABCD... 01J3WXYZ... --db=/var/lib/fleetsweeper/data.db

# Compare a known-good scan against the latest
fleetsweeper whatchanged 01J3ABCD... --db=/var/lib/fleetsweeper/data.db

# Only show findings at warning severity or above
fleetsweeper whatchanged --severity=warning --db=/var/lib/fleetsweeper/data.db
```

## Output

Six scans an hour apart, where one cluster's enforced namespace count
jumped from 24 to 80 at the fourth:

```
Comparing scan-1 -> scan-6
Fleet score: 98 -> 90 (-8)

Drifted clusters (1):
  c04 deviation 0.2 -> 10.0 (+9.8), security/enforced_count 24 -> 80 (z -0.2 -> 14.7), now flagged on security/enforced_count since scan-4

New findings (1):
  [CRITICAL] c04 -- c04 deviates from fleet norm on enforced_count

Cleared findings (0):
  (none)

Cluster score changes:
  c04                             100 (A) ->  72 (C)  -28
```

## The drift ledger

The "Drifted clusters" block reads every stored scan from the older scan
to the newer one, up to 50, not just the two ends. For each cluster it
reports:

- **Deviation mass** at the first and last scan: the sum, over every
  numeric field, of how far the cluster sits from its norm in modified
  z-score terms, each field capped at 10. The norm is the fleet, or the
  cluster's tagged cohort where it has one. Zero means the cluster sits on
  the norm everywhere.
- **The field that moved most**, with its value and z-score before and
  after.
- **Outlier flags gained or lost**, each with the scan where it last
  flipped, so "since scan-4" points at the deploy that caused it. A flag
  the cluster's tagged cohort holds does not count, since it raises no
  finding.

A cluster appears only when one of its own values changed or one of its
flags flipped. A cluster whose z-score moved only because the rest of the
fleet moved around it is left out. Rows are ordered by the size of the
change in deviation mass, largest first. `--json` carries the full ledger
under `drift`, including the per-scan mass series for every listed
cluster.

The dashboard's Drift page draws the same ledger over a window of the last
2, 5, 10, or 24 scans, or a date range, with a sparkline of each cluster's
mass, then the findings that appeared and resolved between the window's
first and last scans, and copies the lot as Markdown. `GET /api/drift`
serves it: `?scans=N` for the newest N scans, or `?since=` and `?until=` in
RFC 3339, with `?scans=` capping how many of that range it keeps.

Findings are matched across scans by fingerprint: cluster, scanner, and
rule. A finding whose title count changes ("3 privileged containers" to
"5") is the same finding, neither new nor cleared. Cluster score deltas are
sorted worst first.

## What if it were fixed?

`fleetsweeper whatif` answers the follow-up question: what happens to the
score and the fleet norm if one cluster's field were brought back in line.
It rebuilds a stored scan with the fix applied and writes nothing.

```bash
fleetsweeper whatif --cluster=c04 --field=security/enforced_count --db=/var/lib/fleetsweeper/data.db
```

```
What if c04 security/enforced_count were fixed (median, fleet norm)?
Fleet score: 90 -> 98 (+8)
Norm: median 25.5 -> 25.25, MAD 2.5 -> 1.75
Newly flagged: none
No longer flagged: c04
Nothing was changed. This is a projection from the stored scan.
```

`--fix` picks the change: `median` for numeric fields, `mode` for string
fields, `consensus` to add the set members the cluster lacks, and `remove`
to take the cluster out of the population. Empty picks the one that fits
the field. `--scope` fixes toward a cohort's norm instead of the fleet's.
Fixing a cluster can move the norm itself, so other clusters can become
outliers once it does, and "Newly flagged" names them. A consensus fix on
ingress classes is refused, since adding a class would mean inventing an
ingress that uses it.

## CI usage

Pair `whatchanged --json --severity=critical` with `jq` for a deploy gate
that fails when a critical finding lands:

```bash
fleetsweeper whatchanged --json --severity=critical \
  --db=/var/lib/fleetsweeper/data.db \
  | jq -e '.new_findings | length == 0'
```

Or fail when the fleet score drops by more than N points:

```bash
delta=$(fleetsweeper whatchanged --json --db=/var/lib/fleetsweeper/data.db \
  | jq '.fleet_score_delta')
if [ "$delta" -lt -5 ]; then
  echo "fleet score dropped $delta points; blocking promotion"
  exit 1
fi
```

Or fail when any cluster gained an outlier flag:

```bash
fleetsweeper whatchanged --json --db=/var/lib/fleetsweeper/data.db \
  | jq -e '[.drift.clusters[].gained // [] | length] | add // 0 | . == 0'
```
