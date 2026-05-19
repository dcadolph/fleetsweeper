# REST API

The full OpenAPI 3.0 specification is served at `/openapi.yaml` and lives in
the repo at [`internal/server/openapi.yaml`](https://github.com/dcadolph/fleetsweeper/blob/main/internal/server/openapi.yaml).

## Authentication

All mutating endpoints require either:

- `--insecure` (development only), or
- `Authorization: Bearer <token>` where `<token>` is either the bootstrap
  `--auth-token` value or a stored API key.

GET endpoints are open to viewers, operators, and admins.

## Common headers

- `Content-Type: application/json; charset=utf-8` on responses.
- `Authorization: Bearer <token>` on requests (omit only when `--insecure`).
- `X-Fleetsweeper-Signature: sha256=<hex>` on inbound webhook calls.

## Endpoint groups

| Path prefix | Purpose |
| --- | --- |
| `/scans` | List, retrieve, trigger, seal scans. |
| `/clusters` | List, inspect cluster detail. |
| `/groups` | Manage cluster groups. |
| `/trends`, `/outliers`, `/forecast`, `/capacity` | Computed analysis over the scan history. |
| `/cost` | Cost correlation (requires `--cost-csv`). |
| `/integrations` | Status of optional integrations (Slack, webhooks, sealing). |
| `/acks` | Finding acknowledgements. |
| `/findings/{fingerprint}/ack` | Per-finding ack management. |
| `/webhooks/scan-trigger` | Inbound HMAC-signed trigger endpoint. |
| `/geo`, `/locations` | Geographic placement and manual overrides. |
| `/contexts` | Available kubeconfig contexts. |
| `/admin/keys` | Manage API keys (admin only). |
| `/admin/audit` | Query the audit log (admin only). |
| `/admin/whoami` | Inspect effective actor identity. |

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
