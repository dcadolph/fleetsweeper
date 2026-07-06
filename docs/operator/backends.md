# Database backends

Fleetsweeper supports two backends through the same `Store` interface.

| Backend | DSN | Suitable for |
| --- | --- | --- |
| SQLite (default) | filesystem path (`/data/fleet.db`) or `:memory:` | Single-instance deployments. Concurrent readers; writes serialized by the SQLite engine. Recommended for fleets up to a few thousand clusters. |
| Postgres | `postgres://user:pass@host:5432/db?sslmode=require` | Multi-replica deployments behind a load balancer; HA via a managed Postgres service. |

Both backends apply the same migrations and store data in compatible shapes,
so the application code is unchanged between them.

## Choosing a driver

Either pass `--db-driver` explicitly or rely on auto-detection from the DSN
prefix:

```shell
fleetsweeper serve --db /data/fleet.db                            # sqlite (default)
fleetsweeper serve --db /data/fleet.db --db-driver sqlite         # explicit
fleetsweeper serve --db 'postgres://fs:secret@db:5432/fleet?sslmode=require'   # auto
fleetsweeper serve --db "$DSN" --db-driver postgres               # explicit
```

## SQLite

The default. Uses `modernc.org/sqlite` (cgo-free) with WAL mode, foreign keys,
and a busy timeout of five seconds. Persist `/data/fleet.db` on a
PersistentVolume in Kubernetes.

WAL means readers and writers do not block each other; one writer at a time
is fine for the workload Fleetsweeper produces (one scan completes every
few seconds at the busy end of the spectrum).

## Postgres

Uses `github.com/jackc/pgx/v5/stdlib`. Connection pooling defaults:

| Setting | Default |
| --- | --- |
| Max open connections | 20 |
| Max idle connections | 5 |
| Connection max lifetime | 30m |

Schema migrations are recorded in the same `schema_migrations` table the
SQLite path uses, so migrating between backends after the fact is a
straightforward dump-and-restore at the row level (when needed).

### Helm

```yaml
database:
  driver: postgres
  postgres:
    # Either inline (creates a generated Secret), or reference an existing one.
    dsn: ""
    existingSecret: fleetsweeper-db
    existingSecretKey: dsn

replicaCount: 3                  # safe with Postgres
persistence:
  enabled: false                 # no per-replica PVC needed
```

The chart wires the DSN into the deployment as `$FLEETSWEEPER_DB_DSN` from
the configured Secret.

### Migration ordering

Migrations are numerically aligned between backends. A row in
`schema_migrations` recorded by SQLite version N matches a row Postgres
version N would have written: both contain the same `version` integer.
This means an operator who initializes a Postgres cluster against
fleetsweeper version 0.2.0 and one who later upgrades to 0.3.0 both end up
at exactly the same schema state.

### When to use which

- **Use SQLite** when one replica is enough. The single binary, no external
  dependencies, and zero-admin Postgres-less deployment is the default
  "everyone wants this" story.
- **Use Postgres** when you need multiple replicas for HA, when your team
  already runs a managed Postgres anyway, or when scan history retention
  goes beyond what a single SQLite file is comfortable with (multi-year
  retention with hundreds of clusters).

You can switch between them at any point by running fleetsweeper against
the new DSN; just back up the old database first.
