# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Fleetsweeper,
**please do not open a public issue.** Report it privately so we can ship a
fix before the details become public.

The preferred channel is GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form. Include reproduction steps and the affected version.

You will receive an acknowledgement within three business days. We aim to
ship a fix within thirty days for high-severity issues, and to credit
reporters in the release notes unless they request otherwise.

## What is in scope

- The Fleetsweeper CLI and server binary.
- The official container image (`ghcr.io/dcadolph/fleetsweeper`).
- The Helm chart and example RBAC manifests in `deploy/`.

## What is not in scope

- Vulnerabilities in upstream dependencies that are already publicly
  disclosed. Open a regular issue so we can bump the dependency.
- Bugs that require an attacker who already has cluster-admin or root on the
  host running Fleetsweeper.
- Denial of service that requires a privileged network position.

## Hardening notes for operators

- Always set `--auth-token` in production. `--insecure` exists only for local
  development and prints a loud warning at startup.
- Do not expose the admin address (`--admin-addr`) to untrusted networks. It
  serves pprof and metrics, which can leak sensitive memory state.
- Set `--cors-origin` to an explicit allowlist. Wildcards are intentionally
  unsupported.
- The bundled RBAC in `deploy/rbac.yaml` grants read-only verbs. Audit it
  before applying with cluster-admin credentials.
- Fleetsweeper never writes to the clusters it scans. If you observe any
  write-shaped behavior, treat it as a security bug and report it.
