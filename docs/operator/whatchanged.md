# `fleetsweeper whatchanged`

After a deploy or an incident, the most useful question is rarely
"what does the fleet look like". It's "what changed since the last
scan." `whatchanged` answers exactly that, comparing two scans and
emitting only the deltas.

## Usage

```bash
# Compare the latest two scans
fleetsweeper whatchanged --db=/var/lib/fleetsweeper/data.db

# Compare specific scans (order: older first)
fleetsweeper whatchanged 01J3ABCD... 01J3WXYZ... --db=/var/lib/fleetsweeper/data.db

# Compare a known-good scan against the latest
fleetsweeper whatchanged 01J3ABCD... --db=/var/lib/fleetsweeper/data.db

# Only show changes at warning severity or above
fleetsweeper whatchanged --severity=warning --db=/var/lib/fleetsweeper/data.db
```

## Output

```
Comparing 01J3ABCD... -> 01J3WXYZ...
Fleet score: 88 -> 73 (-15)

New findings (4):
  [CRITICAL] prod-east. 5 nodes report NotReady
  [CRITICAL] prod-east. Admission webhook unreachable from 2 contexts
  [WARNING]  prod-west. Kube-apiserver memory >85%
  [WARNING]  staging. 3 deployments without resource limits

Cleared findings (1):
  [WARNING] staging. Image audit: 12 containers without digest pin

Cluster score changes:
  prod-east                       91 (A) ->  60 (D)  -31
  staging                         78 (B) ->  82 (B)  +4
```

Findings are matched across scans by
`(cluster, scanner, severity, title)` so a finding that re-fires on
the same cluster with the same title is treated as unchanged rather
than as both new and cleared.

Cluster score deltas are sorted worst-first so the cluster that
regressed the most appears at the top of the list.

## CI usage

Pair `whatchanged --json --severity=critical` with `jq` for a
deploy gate that fails when a critical finding lands:

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
