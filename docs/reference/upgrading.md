# Upgrading

The authoritative upgrade guide lives at the repo root:

- [UPGRADING.md](https://github.com/dcadolph/fleetsweeper/blob/main/UPGRADING.md)

## General process

1. Read every section between your current version and the target.
2. Back up `fleet.db`.
3. Pull the new image (`helm upgrade ...` or `docker pull ...`).
4. Restart. Migrations apply on startup.
5. Confirm `/readyz` returns 200 and the process log shows no migration errors.
