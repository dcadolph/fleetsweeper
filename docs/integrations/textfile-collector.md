# node_exporter textfile collector

For deployments where running a long-lived Fleetsweeper HTTP server is
overkill. Or for clusters whose Prometheus pipeline scrapes
node_exporter and nothing else. The
`fleetsweeper export-metrics` subcommand writes a Prometheus
textfile-collector exposition file you can wire into node_exporter's
`--collector.textfile.directory`.

## Usage

```bash
fleetsweeper export-metrics /var/lib/node_exporter/textfile \
  --db=/var/lib/fleetsweeper/data.db
```

The command:

1. Opens the configured store.
2. Loads the most recent scan.
3. Builds the fleet report.
4. Writes `fleetsweeper.prom` into the output directory, atomically
   (via a `.tmp` rename) so node_exporter never observes a partial
   file.

Rename the file with `--filename` if you colocate multiple exporters
in the same directory.

## What's exposed

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `fleetsweeper_fleet_score` | gauge | `scan_id` | Overall fleet health, 0-100 |
| `fleetsweeper_fleet_score_timestamp_seconds` | gauge |. | Unix time the metrics were written |
| `fleetsweeper_findings_total` | gauge | `severity` | Findings emitted by the latest scan |
| `fleetsweeper_clusters_total` | gauge |. | Number of clusters analyzed |
| `fleetsweeper_cluster_score` | gauge | `cluster`, `grade` | Per-cluster health, 0-100 |
| `fleetsweeper_cluster_outlier` | gauge | `cluster` | Set to 1 for clusters flagged as outliers |

The names match the surface exposed by Fleetsweeper's own
`/metrics` endpoint so dashboards keep working whether you swap from
HTTP scrape to textfile collector or run both side by side.

## Scheduling

The command is one-shot. Run it on whatever cadence makes sense:

```bash
# systemd timer (preferred)
[Unit]
Description=Refresh Fleetsweeper textfile metrics

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fleetsweeper export-metrics \
  /var/lib/node_exporter/textfile \
  --db=/var/lib/fleetsweeper/data.db
User=fleetsweeper

# Pair with:
[Unit]
Description=Refresh Fleetsweeper textfile metrics every 5 min

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

Or a plain crontab line for non-systemd hosts:

```cron
*/5 * * * * fleetsweeper export-metrics /var/lib/node_exporter/textfile --db=/var/lib/fleetsweeper/data.db
```

## Combining with `fleetsweeper scan`

Run the scan and the export in sequence so node_exporter sees fresh
numbers immediately:

```bash
fleetsweeper scan --db=/var/lib/fleetsweeper/data.db
fleetsweeper export-metrics /var/lib/node_exporter/textfile \
  --db=/var/lib/fleetsweeper/data.db
```

This pattern keeps the dashboard "live" without spinning up the
embedded HTTP server.
