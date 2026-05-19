# Versioning

The authoritative versioning policy lives at the repo root:

- [VERSIONING.md](https://github.com/dcadolph/fleetsweeper/blob/main/VERSIONING.md)

## At a glance

- Pre-1.0 (current): minor version is the breaking-change axis; patch
  versions are non-breaking.
- Post-1.0: full [SemVer 2.0.0](https://semver.org/).
- Database schema migrations are forward-only and recorded in
  `schema_migrations`.
- CRDs follow Kubernetes conversion rules; `v1alpha1` is the current served
  version and remains served for one minor release after `v1` ships.
- HMAC webhook signature format (`X-Fleetsweeper-Signature: sha256=<hex>`)
  is stable across versions.
