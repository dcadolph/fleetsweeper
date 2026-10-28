# REST API

The OpenAPI 3.0 specification is served at `/openapi.yaml` and lives in the
repo at [`internal/server/openapi.yaml`](https://github.com/dcadolph/fleetsweeper/blob/main/internal/server/openapi.yaml).
It documents every route the server registers, and a test fails when the two
disagree.

## Authentication

All mutating endpoints require one of:

- `--insecure` (development only),
- `--demo`, whose synthetic in-memory world runs open as anonymous admin, or
- `Authorization: Bearer <token>` where `<token>` is either the bootstrap
  `--auth-token` value or a stored API key.

GET endpoints are open to viewers, operators, and admins. `POST /api/whatif`
is a read too: it projects a fix without writing anything, so viewers may call
it within their cluster scope.

## Common headers

- `Content-Type: application/json; charset=utf-8` on responses.
- `Authorization: Bearer <token>` on requests (omit only when `--insecure` or `--demo`).
- `X-Fleetsweeper-Signature: sha256=<hex>` on inbound webhook calls.

## Endpoints

Paths below are under `/api` unless they start with a root path.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/scans` | List recent scans. `?limit=` caps the count. |
| POST | `/scans` | Trigger a scan of contexts, a group, or every context. |
| GET | `/scans/{id}` | One scan record. |
| GET | `/scans/{id}/report` | The full report of one scan. |
| GET | `/scans/{id}/seal` | A sealed export bundle of one scan (needs `--seal-key`). |
| GET | `/clusters` | Known clusters with their tags and groups. |
| GET | `/clusters/{name}/detail` | One cluster's scanner data, findings, peers, and flagged distributions. |
| GET | `/clusters/{name}/timeline` | One cluster's findings across recent scans. |
| GET | `/clusters/{name}/tags` | One cluster's tags. |
| PUT, DELETE | `/clusters/{name}/tags/{key}` | Set or remove one tag. A `cohort` tag declares the cluster's cohort. |
| GET | `/tags` | Every cluster's tags. |
| GET, POST | `/groups` | List or create cluster groups. |
| DELETE | `/groups/{name}` | Delete a group. |
| GET | `/trends`, `/trends/{cluster}` | Fleet and per-cluster trends over recent scans. |
| GET | `/outliers` | Outliers of the latest scan. `?threshold=` overrides 3.5. |
| GET | `/cohorts` | Cohorts of the latest scan with their outliers. |
| GET | `/cohorts/map` | The two-dimensional cohort map with nearest peers. |
| GET | `/distributions` | The distributions behind the norm. `?scope=`, `?scanner=`, `?field=`. |
| GET | `/distributions/history` | One field's distribution over recent scans. |
| GET | `/score/attribution` | The fleet score with the ledger of what cost it points. |
| GET | `/drift` | The drift ledger over a window of scans. |
| POST | `/whatif` | Project the fleet with one cluster's value fixed to its norm. Writes nothing. |
| GET | `/capacity` | Capacity analysis with correlated signals. |
| GET | `/forecast/fleet-score`, `/forecast/clusters` | Score forecasts one scan interval ahead. |
| GET | `/cost` | Cost correlation (needs `--cost-csv`, or the demo's built-in sheet). |
| GET | `/integrations` | Which optional integrations are on. |
| GET | `/scanners` | Every scanner with its label, description, and category. |
| GET | `/acks` | Active finding acknowledgements. |
| POST, DELETE | `/findings/{fingerprint}/ack` | Acknowledge a finding or remove the acknowledgement. |
| GET | `/findings/timeline`, `/findings/persistence` | Findings over recent scans and how often each recurs. |
| GET | `/alerts` | Inbound AlertManager and Falco alerts, each with its ack state. |
| POST | `/alerts/{fingerprint}/ack` | Acknowledge an inbound alert. |
| POST | `/webhooks/scan-trigger` | HMAC-signed inbound scan trigger. |
| POST | `/webhooks/alertmanager`, `/webhooks/falco` | Inbound alert receivers. |
| GET | `/geo` | Cluster placements with status, deviation mass, and flagged fields. |
| GET | `/locations` | Manual location overrides. |
| PUT, DELETE | `/locations/{cluster}` | Set or remove one override. |
| GET | `/contexts` | Kubeconfig contexts the server can reach. |
| GET | `/events` | Server-sent events. See [Events](events.md). |
| GET, POST | `/admin/keys` | List or create API keys (admin). |
| DELETE | `/admin/keys/{id}` | Revoke an API key (admin). |
| GET | `/admin/audit` | Query the audit log (admin). |
| GET | `/admin/whoami` | The caller's effective identity. |
| GET | `/admin/system` | Version, uptime, features, and storage (admin). |
| GET | root `/healthz`, `/readyz` | Liveness and readiness. |
| GET | root `/openapi.yaml` | The specification. |
| GET | root `/oidc/login`, `/oidc/callback`, `/oidc/logout` | Browser sign-in. See [OIDC](../operator/oidc.md). |

## Error format

All errors are returned as JSON with this shape:

```json
{ "error": "human-readable message", "code": 403 }
```

Status codes follow HTTP conventions. `401` means missing/invalid token;
`403` means the role or scope does not allow the action; `404` means the
resource does not exist; `429` means a scan is already in flight; `5xx`
indicates a server-side fault.

## Pagination

Endpoints that can return large lists support a `limit` query parameter
with sensible defaults (50 for scans, 100 for audit entries). When more
data is needed, narrow the query with filters rather than paginating: most
endpoints are designed for "give me the latest" rather than full history
traversal.
