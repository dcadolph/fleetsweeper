# Production Readiness

What Fleetsweeper ships ready for the box.

| Capability             | Implementation |
| ---------------------- | -------------- |
| HA backend             | SQLite default, PostgreSQL via `--db-driver=postgres` |
| Multi-replica safe     | Kubernetes Lease-based leader election (`coordination.k8s.io/v1`) |
| Multi-tenant RBAC      | Scoped API keys (`admin`, `operator`, `viewer`) with cluster scope (`*`, names, or `group:<n>`) |
| Audit log              | Every mutating request captured. Queryable at `GET /api/admin/audit`. Retention via `--audit-retention` |
| Declarative ops        | `ClusterScan` CRD with an in-process reconciler |
| GitOps integrations    | `FleetDriftReport` CR plus `PolicyReport` (wgpolicyk8s.io) |
| Observability          | Prometheus metrics (server and controller), OpenTelemetry traces, ServiceMonitor template |
| Webhooks               | HMAC-signed inbound trigger plus outbound subscriber dispatch |
| Sealed reports         | HMAC-signed scan archives verifiable with `fleetsweeper verify` |
| Backup and restore     | `fleetsweeper backup` and `fleetsweeper restore` for SQLite, `pg_dump` for Postgres |
| Event stream           | SSE at `/api/events` for reactive dashboards and external consumers |
| Operator hooks         | PDB, NetworkPolicy, and ServiceMonitor templates. `--config FILE` YAML config |
| Versioning             | Stability contract in [versioning.md](reference/versioning.md). Upgrade guide in [upgrading.md](reference/upgrading.md) |
| Onboarding             | `fleetsweeper init` scaffolds a starter folder. Helm post-install `NOTES.txt` walks through next steps |
| Plugin distribution    | krew manifest at `deploy/krew/plugin.yaml` |
| Supply chain           | Multi-arch images with SBOM and Cosign signatures (goreleaser) |

## Where to go next

- [Helm deployment](operator/helm.md). Chart values, RBAC, persistence.
- [Backends](operator/backends.md). SQLite vs Postgres trade-offs.
- [Leader election](operator/leader-election.md). Multi-replica safety details.
- [Audit log](operator/audit.md). What is captured and how to query it.
- [RBAC and API keys](operator/rbac.md). Scoped multi-tenant access.
