# Upgrading Fleetsweeper

This guide tracks behavior changes between releases that operators should
know about before bumping their deployment. See `VERSIONING.md` for the
stability contract and the GitHub release notes for the full feature list.

## General process

1. Read the section for the version you are moving *to* and every section
   between your current version and the target.
2. Back up your SQLite database. The migrations are forward-only.
3. Update the chart (`helm upgrade fleetsweeper ...`) or the binary.
4. Restart fleetsweeper. Schema migrations apply automatically on startup.
5. Verify `kubectl logs deploy/fleetsweeper | grep migrate` shows no errors
   and `/readyz` returns 200.

## v0.13.0

No schema migration. Findings, counts, and some outputs change on the first
scan after the upgrade, because drift detection got stricter about what it
calls drift.

- **Favorable outliers are info, not warnings.** A cluster on the better side
  of the norm for a field with a known direction (e.g. fewer restarts) is
  titled "is better than" the norm, graded info, and the finding suggests a
  cohort tag if the difference is intended.

- **Zero-spread fields can flag exact outliers.** A numeric field where most
  clusters report the same value used to flag nothing. It now flags every
  cluster off that value once at least 60% of the fleet holds it exactly, and
  the finding says "k of n clusters report exactly" the norm.

- **One fact raises one finding.** When an absolute rule and a norm finding
  describe the same field on the same clusters, only one is kept. Expect fewer
  findings and a different Fleet Score on fleets that saw duplicates.

- **Severity counts come from findings.** The summary's critical and warning
  counts are the number of findings at that severity. The per-section
  divergence `severity` field is removed from the report and the API.

- **Two-member tagged cohorts hold their outliers** when both members agree,
  the same way larger cohorts do.

- **Held outliers are not exported.** The Outliers page folds held rows,
  `/api/outliers` returns only findings with a norm, and the Prometheus
  outlier series skip outliers a cohort explains. Expect fewer series.

- **The events scanner drops `total_events` and `normal_events`.** Both were
  always zero.

- **Webhook dedup keys on the finding fingerprint.** The first alert for each
  open finding may be sent once more after the upgrade. A failed delivery is
  no longer recorded as sent, so it is retried on the next scan.

- **PolicyReport `rule` is the finding's rule** (e.g.
  `image-audit/digest-pinning`), not a name taken from the title. Policy
  engine filters keyed on the old rule names need updating.

- **Stricter CLI input.** Enum flags reject unknown values (e.g. `scan -o
  yaml` exits 1 and lists the valid values), `--log-level` rejects unknown
  levels, and `--scanners` names an unknown scanner before connecting. Every
  command honors a PostgreSQL `--db` DSN, `watch --db` saves its scans, and
  `remediate` without `--push` never contacts GitHub. `--probe-registries` is
  defined on `scan`, `serve`, and `watch`.

## v0.12.0

No schema migration. One flag is renamed.

- **`whatif --scope` is now `whatif --norm`.** The flag picks the norm a fix
  moves toward (`fleet` or a cohort name). `apikey create --scope` limits
  what a key can reach, and one name with two meanings read badly. Scripts
  that pass `whatif --scope` fail with `unknown flag: --scope` until renamed.

- **Cluster-admin bindings are judged by the binding.** rbac-audit used to
  treat any binding to a role labeled `kubernetes.io/bootstrapping` as system.
  `cluster-admin` carries that label on every real cluster, so no binding to
  it was ever counted. A binding is now system only when the binding itself
  carries the label or its name starts with `system:` or `kubeadm:`. A binding
  that grants to `system:unauthenticated` or `system:anonymous` is never
  system. Fleets that bind `cluster-admin` by hand will see new
  `rbac-audit/cluster-admin-binding` findings after the first scan. That is
  the rule working, not a regression.

## v0.11.0

No schema migration and no flag changes.

- **Demo mode turns auth off.** `serve --demo` serves a sealed synthetic fleet,
  so the scan trigger, acks, tags, and groups work without a token. An
  `--auth-token` passed with `--demo` is logged as ignored. Outside demo mode
  nothing changed.
- **Cluster score follows cluster status.** A cluster's score now charges its
  own findings and the fleet findings that mark it, at the mark's severity. A
  fleet finding that marks no cluster costs no cluster anything. Scores of
  clusters that were paying for unmarked fleet findings go up.

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

- `api_keys` stores hashed bearer tokens, role, and scope per key.
- `audit_log` records every mutating request.

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
