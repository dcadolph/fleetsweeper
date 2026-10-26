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

## Sealed export bundles

`fleetsweeper export` writes one scan as a `.tar.gz` for handoff to an
auditor. With `--seal-key` (or `FLEETSWEEPER_SEAL_KEY`) the bundle is sealed.

| File | Contents |
| --- | --- |
| `METADATA.txt` | Scan ID, scan time, score, and finding counts. |
| `report.json` | The report, rebuilt from the stored scan. |
| `report.pretty.json` | The same report, indented. |
| `report.html` | The self-contained HTML report. |
| `scan_results.json` | The raw scanner results the report was built from. |
| `policyreports/` | One PolicyReport YAML per cluster. |
| `fleetdrift/` | One FleetDriftReport YAML per cluster. |
| `cost.json` | Cost correlation, only with `--cost-csv`. |
| `MANIFEST` | The SHA-256 of every other file, one `<digest>  <path>` line each. |
| `MANIFEST.sig` | `sha256=<hex>`, the HMAC-SHA256 of `MANIFEST` under the seal key. |

`MANIFEST` uses the `sha256sum` layout, so `sha256sum -c MANIFEST` inside the
unpacked bundle checks the digests without fleetsweeper.

### What verify checks

`fleetsweeper verify bundle.tar.gz --seal-key <key>` fails when:

- `MANIFEST.sig` is not a valid signature of `MANIFEST` under the key, which
  covers a wrong key and an edited `MANIFEST`.
- A file listed in `MANIFEST` is missing or its digest differs.
- The bundle holds a file that `MANIFEST` does not list.
- The archive is not one root directory of regular files, or a path climbs
  out with `..` or appears twice.

A bundle without `MANIFEST` or `MANIFEST.sig` fails as unsealed.

### Determinism

A bundle is a function of the stored scan. The report is rebuilt with the
scan's own timestamp, `METADATA.txt` carries no export time, archive entries
are sorted and stamped with the scan time, so exporting the same scan twice
with the same options writes byte-identical files and the same signature.

`GET /api/scans/{id}/seal` rebuilds the bundle a default export writes
(no `--cost-csv`, `--policy-report-namespace fleetsweeper`) and returns its
signature and `MANIFEST`. An auditor can record that signature at scan time
and later compare it with `MANIFEST.sig` in an export of the same scan. The
endpoint returns 404 when the server runs without `--seal-key`.

`fleetsweeper migrate` keeps scan IDs and timestamps, so a signature recorded
before a move still names the right scan afterward.
