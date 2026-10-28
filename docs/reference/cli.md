# CLI

`fleetsweeper` is one binary with 27 commands. The descriptions below are
each command's own help line; `fleetsweeper <command> --help` lists its flags.
`completion` and `help` come from the CLI framework and are left out.

| Command | Purpose |
| --- | --- |
| `apikey` | Manage API keys for the Fleetsweeper server. |
| `apikey create` | Mint a new API key. |
| `apikey list` | List all API keys (token hashes redacted). |
| `apikey revoke` | Revoke an API key by ID. |
| `backup` | Snapshot the SQLite database to a portable file. |
| `baseline` | Inspect, export, and diff the fleet admission baseline. |
| `baseline diff` | Compare a saved baseline against the current one. |
| `baseline export` | Write the current admission baseline to a YAML file. |
| `baseline show` | Print the current admission baseline as YAML. |
| `compare` | Diff two scans: new vs resolved findings, score delta, cluster status changes. |
| `diagnose` | Check that every configured integration is wired up correctly. |
| `doctor` | Diagnose the local fleetsweeper environment. |
| `drift` | Check every pod in a context against the admission baseline. |
| `export` | Bundle a scan as a tar.gz of report + PolicyReports + FleetDrift + cost. |
| `export-metrics` | Write Prometheus textfile-collector .prom files. |
| `group` | Manage cluster groups. |
| `group add-cluster` | Add clusters to a group. |
| `group create` | Create a cluster group. |
| `group delete` | Delete a group. |
| `group list` | List all groups. |
| `group remove-cluster` | Remove clusters from a group. |
| `history` | View scan history and trends. |
| `history diff` | Compare two scans. |
| `history list` | List past scans. |
| `history prune` | Delete scans older than a cutoff. |
| `history show` | Show details of a past scan. |
| `history trend` | Show fleet drift trends. |
| `init` | Scaffold a starter deployment folder. |
| `location` | Manage manual geographic location overrides for clusters. |
| `location delete` | Delete the manual location for a cluster. |
| `location list` | List all manual location overrides. |
| `location set` | Set the manual location for a cluster. |
| `migrate` | Copy data between Fleetsweeper backends. |
| `recommend` | Prioritized action items derived from the latest scan. |
| `remediate` | Open a GitOps pull request for a Fleetsweeper finding. |
| `restore` | Restore a SQLite snapshot taken by `fleetsweeper backup`. |
| `scan` | Scan clusters and compare configurations. |
| `serve` | Start the web UI and API server. |
| `tag` | Manage cluster tags (env, tier, owner, ...). |
| `tag del` | Remove one tag key from a cluster. |
| `tag list` | List every tag pair across the fleet. |
| `tag set` | Upsert one or more tags on a cluster. |
| `top` | Live, sorted view of fleet clusters by score. |
| `verify` | Verify the HMAC seal of a fleetsweeper export bundle. |
| `version` | Print the version. |
| `watch` | Repeatedly scan and print a diff between consecutive runs. |
| `whatchanged` | Diff two scans: drifted clusters, new and cleared findings, score deltas. |
| `whatif` | Project the score and fleet norm if one cluster's field were fixed. |
| `why` | Explain what a Fleetsweeper finding or scanner means. |

## Global flags

| Flag | Default | Description |
| --- | --- | --- |
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Path to the kubeconfig used by scanners. |
| `--db` | `""` | Database DSN: a SQLite file path, or a `postgres://` URL. Required for stateful commands. |
| `--db-driver` | `""` | `sqlite` or `postgres`. Empty picks from the DSN: a `postgres://` or `postgresql://` prefix means Postgres, anything else SQLite. |
| `--pretty` | `false` | Indent JSON output. |
| `--log-level` | `warn` | One of `debug`, `info`, `warn`, `error`. Logs go to stderr. |

`serve --demo` runs on its own in-memory store seeded with a synthetic fleet
and does not take `--db`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command succeeded. |
| `1` | Any error not listed below. |
| `2` | No cluster in the scan could be reached. |
| `3` | No kubeconfig contexts were given or found. |
| `4` | The command needs `--db` and none was given. |

Errors print to stderr as `error: <message>`. Commands with their own
pass and fail semantics, such as `doctor` and `drift --fail-on-drift`, exit
`1` when they report a failure.
