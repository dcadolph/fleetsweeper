# Audit log

Every mutating request to fleetsweeper is recorded in the `audit_log` table
and exposed at `GET /api/admin/audit` to admin keys.

## What is captured

| Column | Description |
| --- | --- |
| `id` | Time-sortable unique identifier. |
| `timestamp` | RFC3339 nanoseconds when the request was received. |
| `actor_id` | API key identifier (`bootstrap`, `anonymous`, or `key_*`). |
| `actor_name` | Human-readable label at the time of the request. |
| `actor_role` | Effective role at the time of the request. |
| `method` | HTTP verb (`POST`, `PUT`, `DELETE`). |
| `path` | Request path, e.g. `/scans`. |
| `status` | HTTP response status. |
| `remote_addr` | Client transport address. |
| `user_agent` | Client `User-Agent` header. |
| `duration_ms` | Handler duration. |
| `error` | Short excerpt of the response error body when status >= 400. |

## What is not captured

- **GET requests.** They are still logged via the structured process log at
  info level, but recording every dashboard refresh in the audit log would
  overwhelm the table.
- **Request bodies.** Payload contents are not stored, only metadata.
- **Response bodies** beyond the short error excerpt for failures.

## Querying

```text
GET /api/admin/audit?limit=50
GET /api/admin/audit?since=2026-05-17T00:00:00Z
GET /api/admin/audit?actor=key_cli_20260517T100000Z
GET /api/admin/audit?min_status=400
```

Filters compose. The server enforces `limit <= 1000`.

## Retention

The audit table grows unboundedly today. Operators with high mutation
volumes should snapshot and purge externally; a built-in retention flag is
planned and will be additive.
