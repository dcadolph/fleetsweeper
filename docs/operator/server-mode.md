# Server Mode

Run Fleetsweeper as a long-running service with a web dashboard, REST API,
optional scheduled scans, and SSE event stream.

## Minimal start

```
fleetsweeper serve --db fleet.db --addr :8080 \
  --auth-token "$(openssl rand -hex 32)"
```

## With scheduled scans and admin endpoints

```
fleetsweeper serve \
  --db fleet.db \
  --scan-interval 30m \
  --all-contexts \
  --auth-token "$TOKEN" \
  --cors-origin https://fleet.internal \
  --admin-addr 127.0.0.1:9090
```

Keep `--admin-addr` on an internal interface. The admin server exposes
`/debug/pprof/*`, `/metrics`, `/healthz`, and `/readyz`.

## Dashboard

The dashboard provides:

- **Fleet Score** as a single 0-100 hero number with grade, headline, drivers, and a delta vs the previous scan. Designed for a status TV.
- Fleet overview with summary cards.
- Cluster health cards with CPU and memory gauges.
- Findings with severity, named affected resources, and suggested `kubectl` remediation.
- Scan history browser and diff.
- Trend analysis with confidence.
- Outlier detection.
- Cluster grouping.
- CSV export for findings and cluster data.
- Cmd-K command palette and a `?` shortcuts overlay for keyboard-driven use.

## Security

By default, mutating endpoints (`POST /api/scans`, `POST /api/groups`,
`DELETE /api/groups/...`) return 403 because `serve` will scan whatever
kubeconfig the process holds. Two ways to allow mutations:

1. **Recommended**: set `--auth-token` to a long random string. Clients must send `Authorization: Bearer <token>` on mutating requests. Comparison is constant-time.
2. **Explicit opt-out**: pass `--insecure` to disable authentication entirely. A loud warning is logged at startup.

CORS is refused by default. Pass `--cors-origin https://your-ui`
(repeatable) to allow explicit origins. Wildcard origins are intentionally
not supported.

Error responses returned to clients are sanitized. Full error detail is
logged via structured logging.

## API endpoints

```
GET    /healthz                    Liveness probe (unauthenticated)
GET    /readyz                     Readiness probe (pings the store)
GET    /api/scans                  List scans (with ?limit=N)
GET    /api/scans/{id}             Get scan metadata
GET    /api/scans/{id}/report      Get full computed report for a scan
POST   /api/scans                  Trigger a new scan (auth required)
GET    /api/clusters               List all known clusters
GET    /api/clusters/{name}/detail Full scanner data for a cluster
GET    /api/groups                 List groups
POST   /api/groups                 Create a group (auth required)
DELETE /api/groups/{name}          Delete a group (auth required)
GET    /api/trends                 Fleet trend analysis
GET    /api/trends/{cluster}       Per-cluster trend analysis
GET    /api/outliers               Outlier detection on latest scan
GET    /api/forecast/fleet-score   Forecast the next Fleet Score from history
GET    /api/forecast/clusters      Per-cluster score forecasts ranked by trajectory
GET    /api/cost                   Cost-correlated analysis (requires --cost-csv)
GET    /api/capacity               Capacity correlator output for latest scan
GET    /api/events                 SSE stream of scan and integration events
```

See [`docs/reference/api.md`](../reference/api.md) for the full schema and
[`docs/reference/events.md`](../reference/events.md) for SSE event types.
