# Versioning

Fleetsweeper follows [Semantic Versioning 2.0.0](https://semver.org/) once it
reaches v1.0.0. During the pre-1.0 phase the major version is held at zero
and the *minor* version is treated as the breaking-change axis. Releases
remain frequent and additive but minor bumps may include incompatible API or
schema changes; patch bumps will not.

## Stability surface

Once v1.0.0 ships the following surfaces become part of the public contract:

| Surface | Stability | Notes |
| --- | --- | --- |
| CLI flags on `serve`, `scan`, `apikey`, `group`, `compare`, `verify` | Stable | Removal or renaming is a breaking change. |
| REST endpoints under `/api/` | Stable | New endpoints are additive; existing response fields are not removed. |
| ClusterScan CRD `v1` group | Stable | The `v1alpha1` group remains served for one minor release after `v1` ships and is removed thereafter. |
| FleetDriftReport CRD `v1` group | Stable | Same migration policy as ClusterScan. |
| Database schema | Stable via migrations | Forward-only migrations applied automatically on startup. Downgrades are not supported. |
| Prometheus metric names and labels | Stable | Additions are non-breaking. |
| Helm chart values | Stable | Removed keys are documented in `UPGRADING.md` with a removal release. |
| HMAC webhook signature format | Stable | The `X-Fleetsweeper-Signature` header value remains `sha256=<hex>`. |

The following surfaces are explicitly *not* stable and may change in any
release:

- Internal Go package APIs (`internal/...`). Importers should pin a commit
  or fork.
- Demo data, demo IDs, and synthetic geo points.
- The HTML report layout (subject to UX iteration).
- The shape of `pprof` and `/debug/*` endpoints.

## CRD version lifecycle

A new CRD version (for example `v1beta1` or `v1`) is introduced *served* and
*non-storage* in one release, promoted to storage in a later release, and the
prior version is removed two releases after that. The conversion strategy is
declared on the CRD when both versions coexist. The release notes always
state the served / storage version pair for each release.

## Database migrations

Migrations are append-only and forward-only. Each migration has a monotonic
integer version and is recorded in `schema_migrations`. Re-running fleetsweeper
against a database that has already applied the latest migration is a no-op.

Operators upgrading across multiple releases can either run the new binary
once against the old database (the migrations replay in order) or stop the
service, take a backup, and start the new binary. The latter is recommended.

## Pre-1.0 commitments

Even before v1.0.0 the project commits to:

- Forward-only schema migrations: a fresh install at version N always works,
  and an in-place upgrade from any earlier version applies missing migrations
  in order without operator intervention.
- HMAC signature format on inbound and outbound webhooks does not change.
- The Fleet Score range `0..100` and grade letters `A..F` are stable.
- The bearer token authentication scheme is preserved.
- API key role names (`admin`, `operator`, `viewer`) are preserved.

## How releases are tagged

Releases are produced by `goreleaser` from a signed tag of the form `vX.Y.Z`.
Container images are pushed to `ghcr.io/dcadolph/fleetsweeper:vX.Y.Z` and
`:latest`. Both images are SBOM-attested and Cosign-signed.

## Reporting a breaking change

If you find behavior that changed between releases and is not documented in
`UPGRADING.md`, open an issue with the label `breaking-change`. The
maintainers either document the change or revert it in the next patch.
