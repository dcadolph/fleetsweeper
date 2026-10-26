# Pinning and auditing the admission baseline

The admission webhook compares incoming pods against a fleet-derived
baseline of fractions (digest-pinned, non-root, named-SA, etc.). That
baseline changes every time a new scan lands. For most teams that
self-tuning behavior is the feature: as the fleet improves, the bar
moves with it. For teams running `mode: enforce`, a sudden drop in any
fraction is a footgun. Every new pod silently passes a stricter check
on Monday than it did on Friday, or vice versa.

The `fleetsweeper baseline` subcommand exists so you can pin the
fleet norm to a file, check it into git, serve it to the webhook, and fail CI when
the live baseline drifts beyond a tolerance you control.

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
values.

## Serve the pinned baseline

```bash
fleetsweeper serve --db=/var/lib/fleetsweeper/data.db \
  --admission-addr=:8443 --admission-mode=enforce \
  --admission-baseline=./baseline/fleet.yaml
```

With `--admission-baseline` the webhook checks every pod against the
file and ignores the scans in the store, so the bar only moves when you
commit a new file. The file is read once at startup. It is validated
strictly: an unknown field, a fraction outside `[0, 1]`, or a negative
sample count stops `serve` with an error, so a typo cannot pin a norm
you did not mean. A file below the minimum sample (30 containers across
10 pods) loads with a warning, and the webhook then evaluates nothing.

A pinned baseline skips the [stability gate](admission-webhook.md#stability-gate),
since it does not change between scans. It matters most in enforce mode,
where it is the difference between a rule you chose and a rule the last
scan chose for you.

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

A clean diff is a no-op. A regression is a hard failure that surfaces
the field, the saved value, the current value, and the signed delta.
`diff` reads the saved file with the same strict validation as `serve`.
