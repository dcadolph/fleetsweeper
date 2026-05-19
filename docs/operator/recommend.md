# `fleetsweeper recommend`

The drift report tells you what's broken; `fleetsweeper recommend`
tells you what to do about it, ranked by leverage. A remediation that
would fix the same problem on ten clusters at once outranks the same
remediation applied to a single cluster — that's where operator
effort goes furthest.

## Usage

```bash
# Top recommendations from the latest scan
fleetsweeper recommend --db=/var/lib/fleetsweeper/data.db

# Limit to critical-severity issues
fleetsweeper recommend --severity=critical --db=/var/lib/fleetsweeper/data.db

# JSON for downstream tooling
fleetsweeper recommend --json --limit=10 --db=/var/lib/fleetsweeper/data.db
```

## Output

```
1. [WARNING] Pods missing resource limits
   Scanner:  workload-security
   Leverage: 7 cluster(s) — prod-east, prod-west, staging, dev-1, dev-2 (+2 more)
   Run:      kubectl get deploy -A -o json | jq '.items[] | select(.spec.template.spec.containers[] | .resources.limits | not) | .metadata.name'

2. [CRITICAL] Default ServiceAccount in use
   Scanner:  workload-security
   Leverage: 3 cluster(s) — payments, billing, orders
   Apply:
     apiVersion: v1
     kind: ServiceAccount
     metadata:
       name: app
       namespace: payments

3. [WARNING] Container image not digest-pinned
   Scanner:  image-audit
   Leverage: 2 cluster(s) — prod-east, prod-west
   Runbook:  https://runbooks.example/digest-pinning
```

The scoring formula is intentionally simple:

```
score = leverage * (severity_rank + 1)
critical = 3, warning = 2, info = 1
```

Identical remediations across clusters are collapsed by
`(scanner, title)`. Severity within a group is promoted to the
highest seen — a remediation that's "warning on staging, critical on
prod" is presented as critical.

## What gets included

Only findings whose `Remediation` field is populated by the
producing scanner are surfaced. Findings without a concrete fix are
excluded from `recommend` (they still show up in the dashboard and
`/api/scans/{id}/report`).

A scanner adds a `Remediation` by attaching one or more of:

- `Command` — a kubectl/CLI invocation, parameterised with the actual
  offending resource names so the operator doesn't have to
  re-discover them.
- `YAML` — a baseline manifest snippet (default-deny NetworkPolicy,
  PSS-restricted ResourceQuota, etc.) ready to `kubectl apply -f`.
- `RunbookURL` — a link to an internal runbook your team has wired up.

## CI usage

Pair `recommend --json --limit=1` with a deploy gate when the
remediation list has a critical entry:

```bash
top=$(fleetsweeper recommend --json --severity=critical --limit=1 \
  --db=/var/lib/fleetsweeper/data.db | jq '.[0].leverage // 0')
if [ "$top" -gt 0 ]; then
  echo "critical fleet-wide remediation pending; deploy blocked"
  exit 1
fi
```

## Compared to `whatchanged`

| | `whatchanged` | `recommend` |
| --- | --- | --- |
| Input | Two scans | Latest scan |
| Output | New/cleared findings | Prioritised action list |
| Hero metric | Score delta | Leverage |
| Use | Post-deploy verification | Next-deploy planning |

Use them together: `whatchanged` after a release to confirm intent,
`recommend` before the next release to plan the highest-leverage fix.
