# RBAC and API keys

Fleetsweeper has two authentication paths, designed to coexist:

1. **Bootstrap token** (`--auth-token`): a single string passed at startup.
   Treated as a built-in admin. Convenient for development and for minting
   the first scoped key in production.
2. **API keys** stored in the database: each key has a role, optional
   cluster scope, and optional expiry. Created via either the CLI or the
   admin API.

## Roles

| Role | Permissions |
| --- | --- |
| `admin` | Everything, including key management and audit log. |
| `operator` | Trigger scans, acknowledge findings, and manage tags and locations within scope. Cannot manage groups or keys. |
| `viewer` | Read-only. Cannot reach `/admin/*`. |

Read-only endpoints (GET) are open to viewers and above (or to anyone when
`--insecure` is set). Mutating endpoints require `operator` or `admin`.

## Cluster scope

Each key carries `cluster_scope`, a JSON array. The semantics are:

- `["*"]`. Unrestricted (default).
- `["prod-east", "prod-west"]`. Exact match against context name.
- `["group:prod"]`. Any current member of the named group. Membership is
  resolved per request, so adding a cluster to a group immediately broadens
  the key's authority.
- Combinations: `["prod-east", "group:edge", "*"]`. `*` wins.

Cluster scope is enforced on:

- `POST /api/scans`. The contexts list is filtered to the key's scope. A
  request becomes 403 only when no contexts remain.
- `PUT /api/locations/{cluster}` and `DELETE /api/locations/{cluster}`.
- `PUT /api/clusters/{name}/tags/{key}` and
  `DELETE /api/clusters/{name}/tags/{key}`.
- `POST /api/whatif`, against the cluster the request names.
- `POST /api/findings/{fingerprint}/ack` and
  `DELETE /api/findings/{fingerprint}/ack`.
- `POST /api/alerts/{fingerprint}/ack`, against the cluster stored on the
  alert. An alert with no cluster needs a key with `*` scope.

Acks resolve the cluster on the server. The ack body carries only `ack_by`,
`reason`, and `snooze_until`, and a body that names `cluster`, `scanner`, or
`title` is rejected with 400. To create an ack, the server finds the finding
with that fingerprint in the latest report and checks the key's scope against
the finding's cluster. A fingerprint that no current finding carries returns
404. To remove an ack, the server checks the cluster stored on the ack. A
fleet-scoped finding or ack (cluster `fleet`) needs a key with `*` scope, so a
key scoped to `prod-east` cannot silence a fleet-wide finding.

Group management (`POST /api/groups`, `DELETE /api/groups/{name}`) needs
the `admin` role. An operator is refused even with `*` scope. A group widens
every key scoped to it, so defining one is an admin act.

Cluster scope limits writes. Most read endpoints are not scoped, so a key
scoped to `prod-west` can still read the findings and full scanner results of
`prod-east`. Treat any caller that can read the API as able to see the whole
fleet.

`POST /api/webhooks/scan-trigger` takes no API key. Its HMAC secret is the
authority, and a request signed with that secret may scan any context. Guard
the secret as you would an admin token.

## Creating a key

CLI (works offline, before the server is running):

```shell
fleetsweeper apikey create --db /data/fleet.db \
  --name ci-runner \
  --role operator \
  --scope 'group:prod' \
  --ttl 720h \
  --pretty
```

Admin API (requires an existing admin token):

```shell
curl -X POST -H "Authorization: Bearer $BOOTSTRAP" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-runner","role":"operator","cluster_scope":["group:prod"],"ttl":"720h"}' \
  https://fleetsweeper.example.com/api/admin/keys
```

The response contains the raw token. Save it now. The server stores only
its SHA-256 hash and cannot reveal it again.

## Listing and revoking

```shell
curl -H "Authorization: Bearer $ADMIN" https://.../api/admin/keys
curl -X DELETE -H "Authorization: Bearer $ADMIN" https://.../api/admin/keys/key_test_1
```

Revoked keys are retained so audit log entries that reference them stay
interpretable.

## Audit log

Every mutating request is recorded:

```shell
curl -H "Authorization: Bearer $ADMIN" 'https://.../api/admin/audit?limit=50&min_status=400'
```

Filters:

- `since=<RFC3339>`. Only entries strictly newer than this time.
- `actor=<keyID>`. Restrict to one actor.
- `min_status=<N>`. Only responses with status ≥ N (use 400 to see failures).
- `limit=<N>`. Cap rows returned. Server-enforced maximum is 1000.

Audit entries include actor identity, method, path, status, duration, and
a short error excerpt for failures. Read-only requests are not audited to
keep the volume manageable. They are still captured by the request log at
info level.

## Whoami

`GET /api/admin/whoami` returns the calling actor's effective identity,
which the dashboard uses to hide controls a viewer cannot use.

## Bootstrap workflow

A fresh deployment looks like this:

1. Generate a long random string. Set it as `--auth-token` (or
   `FLEETSWEEPER_AUTH_TOKEN`).
2. Start fleetsweeper. The token grants admin access.
3. Mint a scoped operator key per pipeline:
   `fleetsweeper apikey create --name ci-prod --role operator --scope 'group:prod'`
4. Hand the scoped key to that pipeline. Rotate the bootstrap token to
   long-term storage as the emergency credential.
5. Use `GET /api/admin/audit` to confirm the pipelines are using their own
   keys and the bootstrap token is no longer being used in normal traffic.
