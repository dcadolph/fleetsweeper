# CLI

`fleetsweeper` is a single binary with a small set of subcommands.

| Command | Purpose |
| --- | --- |
| `scan` | One-shot scan, write a report (JSON or HTML). |
| `serve` | Run the API + dashboard, optionally with scheduler and controller. |
| `apikey create / list / revoke` | Manage API keys offline. |
| `group create / list / delete` | Cluster group management. |
| `history` | Inspect stored scan history. |
| `location` | Manage manual cluster geolocation overrides. |
| `compare` | Diff two stored scans. |
| `diagnose` | Run targeted single-scanner audits. |
| `export` | Export stored scans as JSON or HTML bundles. |
| `top` | Show the top-N outliers / regressions. |
| `verify` | Verify the HMAC seal of a sealed scan. |
| `watch` | Tail running scans in real time. |
| `why` | Explain a finding in plain English. |
| `remediate` | Open a GitOps PR for a finding with inline YAML remediation. |
| `version` | Print version, commit, and build date. |

## Global flags

| Flag | Default | Description |
| --- | --- | --- |
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Path to the kubeconfig used by scanners. |
| `--db` | `""` | SQLite database path. Required for stateful subcommands. |
| `--pretty` | `false` | Indent JSON output. |
| `--log-level` | `warn` | One of `debug`, `info`, `warn`, `error`. |

See `fleetsweeper <command> --help` for per-command flags.
