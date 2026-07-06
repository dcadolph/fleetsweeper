# Upgrading Fleetsweeper

This guide tracks behavior changes between releases that operators should
know about before bumping their deployment. See `VERSIONING.md` for the
stability contract and `CHANGELOG.md` for the full feature list.

## General process

1. Read the section for the version you are moving *to* and every section
   between your current version and the target.
2. Back up your SQLite database. The migrations are forward-only.
3. Update the chart (`helm upgrade fleetsweeper ...`) or the binary.
4. Restart fleetsweeper. Schema migrations apply automatically on startup.
5. Verify `kubectl logs deploy/fleetsweeper | grep migrate` shows no errors
   and `/readyz` returns 200.

## Unreleased

### Added

- **API keys with roles and cluster scoping.** Mutating endpoints now resolve
  the calling actor from either the legacy `--auth-token` (continues to work
  and is treated as a built-in admin) or from a per-key bearer token minted
  with `fleetsweeper apikey create` or `POST /api/admin/keys`. Roles are
  `admin`, `operator`, and `viewer`. Cluster scope can be `*`, a list of
  cluster names, or `group:<name>` entries.
- **Audit log.** Every mutating request is recorded in the `audit_log` table
  and exposed under `GET /api/admin/audit` for admin keys. The legacy request
  log continues to record read-only traffic at info level.
- **ClusterScan CRD + controller.** A new `--controller` flag on `serve`
  enables a reconciler that watches `fleetsweeper.io/v1alpha1` ClusterScan
  resources and triggers scans on their declared interval. Status is written
  back to the resource so `kubectl get clusterscan` shows live state.
- **CLI: `fleetsweeper apikey {create,list,revoke}`** for offline key
  bootstrapping. The first admin key can be minted before the server starts
  without needing another admin key.

### Schema migrations

Migration v5 adds two tables:

- `api_keys` — stores hashed bearer tokens, role, and scope per key.
- `audit_log` — records every mutating request.

Existing data is untouched. Operators upgrading do not need to do anything;
the migration runs automatically on first startup.

### Recommended upgrade actions

After the upgrade, mint a scoped key for each pipeline that previously used
the global `--auth-token`:

```shell
fleetsweeper apikey create --db /data/fleet.db \
  --name ci-runner \
  --role operator \
  --scope 'group:prod' \
  --ttl 720h
```

Update CI configs to use the new token; rotate the bootstrap `--auth-token`
to a long random string and treat it as the emergency admin credential.

If you run the operator, install the CRD and grant the controller permission
to watch it:

```shell
kubectl apply -f deploy/crds/clusterscan.yaml
helm upgrade fleetsweeper deploy/helm/fleetsweeper \
  --set controller.enabled=true \
  --set controller.namespace=fleetsweeper
```

### Notes

- The legacy `--auth-token` flag continues to work and is now treated as a
  built-in admin token. It is acceptable for development and for bootstrapping
  the first admin key in production. Long-term, prefer named keys for every
  consumer so the audit log carries useful identity.
- The bearer auth path is unchanged from a client's perspective: send
  `Authorization: Bearer <token>` and the server resolves the role and scope
  on the back end.

### Migrating between backends

`fleetsweeper migrate` copies every row from a source backend to a
destination backend using the public `Store` interface:

```shell
fleetsweeper migrate \
  --from /var/lib/fleetsweeper/fleet.db \
  --to "postgres://fs:secret@db:5432/fleet?sslmode=require"
```

The destination must be a fresh database (the schema migrations run on
open). Pass `--force` to allow merging into a non-empty destination.

### Postgres backend (optional)

A new Postgres backend lives behind the same `Store` interface as SQLite.
SQLite remains the default; nothing changes for existing deployments. To
opt in, switch the DSN and driver:

```shell
fleetsweeper serve \
  --db 'postgres://fs:secret@db:5432/fleet?sslmode=require' \
  --db-driver postgres
```

In Helm:

```yaml
database:
  driver: postgres
  postgres:
    existingSecret: fleetsweeper-db
    existingSecretKey: dsn
replicaCount: 3
persistence:
  enabled: false
```

The chart wires the DSN as `$FLEETSWEEPER_DB_DSN` from the named Secret.
Migrations apply automatically on first startup. See
[`docs/operator/backends.md`](docs/operator/backends.md) for the full
discussion.
