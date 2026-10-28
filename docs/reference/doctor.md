# fleetsweeper doctor

`fleetsweeper doctor` is the operational diagnostic command. Run it after
install, after every config change, and from monitoring scripts that need
to gate alerts on real readiness.

## Usage

```shell
fleetsweeper doctor \
  --db /var/lib/fleetsweeper/fleet.db \
  --kubeconfig $HOME/.kube/config \
  --addr https://fleetsweeper.example.com \
  --token "$FLEETSWEEPER_AUTH_TOKEN"
```

Output is human-friendly by default:

```text
fleetsweeper doctor. 2026-05-17T15:00:00Z

  status   check              detail
  ------   -----              ------
  ok       database           sqlite reachable at /data/fleet.db
  ok       kubeconfig         5 contexts available
  ok       contexts           5/5 contexts reachable
  ok       crds               ClusterScan + FleetDriftReport CRDs present
  ok       server             https://fleetsweeper.example.com healthy

summary: 5 ok, 0 warn, 0 fail, 0 skip
```

For monitoring, pass `--json`:

```text
{
  "generated": "2026-05-17T15:00:00Z",
  "checks": [...],
  "summary": { "ok": 5 }
}
```

## Checks

| Check | What it verifies |
| --- | --- |
| `database` | Driver auto-detected, DSN opens, `Ping` succeeds. Skipped when `--db` is empty. |
| `kubeconfig` | File exists at `--kubeconfig`, parses, and lists ≥1 context. |
| `contexts` | Each context in the kubeconfig produces a working client. Mixed results escalate to `warn`; total failure is `fail`. |
| `crds` | `clusterscans.fleetsweeper.io` and `fleetdriftreports.fleetsweeper.io` CRDs are installed. `warn` if missing (lets you ramp on without the controller). |
| `server` | `--addr/healthz` and `/readyz` return 200. Only runs when `--addr` is provided. |

With `--in-cluster`, three more checks probe a deployed release:

| Check | What it verifies |
| --- | --- |
| `leader-lease` | The Lease named for the release exists in `--namespace` and has a holder. `warn` when the Lease is missing or unheld. |
| `admission-webhook` | The `<release>-admission` ValidatingWebhookConfiguration exists, has webhooks, and each has a CA bundle or Service reference. `warn` when absent, `fail` when a webhook has neither. |
| `scan-freshness` | The newest scan in `--db` is younger than `--scan-freshness`. `warn` when no scans exist, `fail` when stale. |

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--in-cluster` | `false` | Run the leader-lease, admission-webhook, and scan-freshness checks. |
| `--namespace` | `fleetsweeper` | Namespace the Helm release was installed into. |
| `--release` | `fleetsweeper` | Helm release name. Names the Lease and the `<release>-admission` webhook configuration. |
| `--scan-freshness` | `24h` | Maximum age of the newest scan before `scan-freshness` fails. |
| `--timeout` | `10s` | Per-check timeout. |

## Exit codes

- `0`. Every check returned `ok` or `skip`.
- `1`. At least one `fail`. The error message is `doctor reported failures`.

`warn` does not influence the exit code; it surfaces concerns without
breaking pipelines.

## Use cases

- **Post-install verification**: run after `helm install` to confirm the
  database is writable and CRDs landed.
- **Pre-flight in CI**: gate a "fleetsweeper-managed" deployment pipeline
  on a clean doctor report.
- **Monitoring**: poll with `--json` every minute and alert on `fail`
  count > 0.
- **Debugging a slow scan**: the per-context reachability check often
  catches the one cluster whose token expired before you do.
