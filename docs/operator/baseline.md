# Pinning and auditing the admission baseline

The admission webhook compares incoming pods against a fleet-derived
baseline of fractions (digest-pinned, non-root, named-SA, etc.). That
baseline changes every time a new scan lands. For most teams that
self-tuning behaviour is the feature: as the fleet improves, the bar
moves with it. For teams running `mode: enforce`, a sudden drop in any
fraction is a footgun. Every new pod silently passes a stricter check
on Monday than it did on Friday, or vice versa.

The `fleetsweeper baseline` subcommand exists so you can pin the
fleet norm to a file, check it into git, and fail CI when the live
baseline drifts beyond a tolerance you control.

## Inspect the current baseline

```bash
fleetsweeper baseline show --db=/var/lib/fleetsweeper/data.db
```

Prints the baseline as YAML, including the `source_scan_id` it was
derived from. Every field is bounded to `[0, 1]`.

## Pin the baseline

```bash
fleetsweeper baseline export --db=/var/lib/fleetsweeper/data.db \
  ./baseline/fleet.yaml
```

Commit `baseline/fleet.yaml` to the same repo that owns your Helm
values. Pair the file with the
[`admission.mode`](admission-webhook.md) you intend to roll out. A
pinned baseline only matters when the webhook is running in enforce.

## Diff in CI

```bash
fleetsweeper baseline diff --db=/var/lib/fleetsweeper/data.db \
  --epsilon=0.05 ./baseline/fleet.yaml
```

`--epsilon` is the maximum allowed delta per fraction; the default
`0.05` (five percentage points) catches large regressions while
tolerating ordinary scan-to-scan jitter. The command exits non-zero
when any fraction has drifted further than that, so dropping it into a
GitHub Action protects against the case where a misconfigured cluster
pulls the fleet norm in an unwanted direction.

Sample output:

```
field                                  saved   current     delta
-----                                  -----   -------     -----
digest_pin_fraction                    0.910     0.870    -0.040
non_root_fraction                      0.820     0.780    -0.040
no_privilege_escalation_fraction       0.790     0.740    -0.050
named_service_account_fraction         0.860     0.820    -0.040
read_only_root_fs_fraction             0.420     0.430    +0.010
```

A clean diff is a no-op; a regression is a hard failure that surfaces
the field, the saved value, the current value, and the signed delta.
