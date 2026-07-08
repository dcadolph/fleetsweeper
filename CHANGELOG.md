# Changelog

All notable changes to Fleetsweeper are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches v1.0.0.

## [0.8.0] - 2026-07-07

Drift replay and finding persistence. The dashboard can now replay how findings
appeared and resolved across recent scans, and each finding is classed by how
persistently it recurs, an implicit signal of standing problems versus passing
blips.

### Added

- Drift replay: a dashboard view that scrubs through recent scans and shows the
  findings present at each point in time, with the counts that appeared and
  resolved since the previous scan. Backed by a new `GET /api/findings/timeline`
  endpoint that rebuilds fleet findings for the recent scan window.
- Finding persistence: `GET /api/findings/persistence` classes each finding as
  chronic, intermittent, or transient by how often it recurs across the scan
  window, cross-referenced with acknowledgements. Surfaced in the drift replay
  view. Recurrence is used because the data carries no explicit resolution
  label, so it is the strongest learned severity signal available.

### Changed

- The finding fingerprint helper moved to `internal/util` so the store, report,
  and server packages share one implementation.

## [0.7.0] - 2026-07-07

A Go client SDK and stability fixes. Applications can now call the Fleetsweeper
API through a typed standard-library client that mirrors the OpenAPI spec,
verified by in-process contract tests against the real server.

### Added

- Go SDK in the `client` package: a standard-library HTTP client that mirrors
  `internal/server/openapi.yaml`, with in-process contract tests that exercise
  the real server through a new `Server.Handler()`. The tests confirmed and
  documented that `GET /api/groups` returns `Group` objects.
- A 60-second quickstart in the getting-started guide.

### Fixed

- Stable scan ordering: `ListScans`, `GetClusterHistory`, and
  `GetScansByTimeRange` break same-second RFC3339 timestamp ties with a
  secondary sort on id, so latest and previous scans no longer swap
  nondeterministically in either backend.
- Nil command context: a cobra command run outside `Execute` has a nil
  `Context()`, which hung a `database/sql` context call. A helper now anchors a
  background context so those calls proceed.

### Changed

- Release and CI workflow actions moved off the deprecated Node 20 runtime
  (checkout v7, setup-go v6, goreleaser-action v7, attest-build-provenance v4).

## [0.6.0] - 2026-07-07

Test hardening and a moving landing page. Broad new test coverage with parser
fuzzing across the CLI, server, store, and admission paths, plus an animated
README hero and banner.

### Added

- Table-driven tests across cmd, admission, server, store, and tracing, plus Go
  fuzz targets for the certificate PEM, image-reference, PolicyReport,
  AlertManager, and Falco parsers.
- Animated SVG hero and banner on the README landing page.

## [0.5.0] - 2026-07-07

Signed releases and fleet-scale resilience. Release artifacts are now cosign
keyless-signed with SLSA provenance, and each scanner runs under a timeout so a
hung cluster cannot stall the sweep.

### Added

- Cosign keyless signatures for the release checksums, produced in CI from the
  release workflow's OIDC identity, plus SLSA build provenance attached to the
  archives and checksums. Verify the checksums with `cosign verify-blob` against
  the release workflow identity and the GitHub Actions OIDC issuer.
- Per-scanner timeout (`--scanner-timeout`, default 60s) across the scan, watch,
  and server sweeps, so a hung API call on one cluster is abandoned and recorded
  as degraded coverage instead of stalling the fleet.
- A 200-cluster build benchmark to guard against engine scale regressions.

## [0.4.0] - 2026-07-07

Incidents and an executive brief. Correlated findings now fuse into incidents,
and the dashboard surfaces incidents, degraded coverage, and a one-glance brief.

### Added

- Incident fusion. Findings that share a root cause on a cluster (admission
  control, node pressure, or security posture) fuse into a single incident with
  the highest member severity and a templated root-cause summary, surfaced on
  the report and the scan CLI.
- Dashboard Incidents page and a degraded-coverage banner, so correlated
  symptoms read as one incident and partial coverage is never mistaken for a
  clean fleet.
- Deterministic executive brief: a templated one-glance summary of the score,
  the worst incident, cohort drift, degraded coverage, and the top fixes, on the
  dashboard hero, the scan CLI, and the report JSON.

## [0.3.0] - 2026-07-07

Time-aware detection and a demo that runs the real engine. Cohort drift now
reaches the fleet score, a cluster that diverges from its own history is
flagged, and serve --demo exercises the actual outlier engine.

### Added

- Within-cohort outliers now become findings, so a cluster that drifts from its
  cohort (not just the fleet) reaches the fleet score, ranked recommendations,
  alerts, and the scan CLI. Deduped against fleet-wide outliers.
- Self-drift detection. Each per-cluster metric series is scanned for its change
  point, and a shift whose recent segment is far from the cluster's own
  pre-change median and MAD is flagged on the history CLI and the per-cluster
  trends endpoint.
- Property and fuzz tests for the MAD outlier engine that pin its invariants and
  guard against non-finite deviations.

### Changed

- serve --demo now synthesizes per-cluster scanner results and runs them through
  the real report engine, so the demo exercises outlier detection, cohort
  baselining, and degraded coverage instead of hand-faked sections.
- The outlier engine caps an infinite modified z-score, which a negligibly small
  MAD could produce, to a finite JSON-safe value instead of emitting an infinity.

## [0.2.0] - 2026-07-07

Trust and polish release. Scanners can no longer report a false all-clear on an
unreachable or forbidden API, the cinematic explainer gained audio, and the
dashboard shed its em-dashes.

### Added

- Per-scanner trust state. Every scan result now carries a state (ok, degraded,
  errored, or unavailable) and a reason. A failed or forbidden scan is recorded
  as errored and kept out of the fleet statistics instead of reading as a clean,
  zero-resource cluster. The report exposes a `degraded` list and each cluster's
  degraded-scanner count, and the CLI prints "N of 24 scanners degraded on
  cluster X" to stderr.
- Procedural audio for the `/cinematic` explainer. A muted-by-default WebAudio
  ambient bed retunes per scene with a soft transition cue and a header toggle.
  It starts on the first user gesture and suspends on pause or tab-hidden, with
  no audio assets.

### Changed

- Error-swallowing scanners now fail loudly. clusterinfo, crd, and geo propagate
  list errors; admission, certs, workloadcoverage, and rbacaudit mark partial
  results degraded; vulnerabilities, metrics, and policyreportingest distinguish
  a genuinely absent feature (unavailable) from a real API failure (errored), so
  a forbidden metrics API is no longer reported as "not installed".
- The top-left Fleetsweeper brand returns to the landing view from both the
  dashboard and the cinematic.

### Removed

- Em-dashes across the dashboard, help text, exported markdown, and cinematic
  captions.

## [0.1.2] - 2026-07-07

Test-coverage release. Adds unit tests for the twelve remaining scanners (now
90 to 100 percent each), removes a stale duplicate OpenAPI spec, and lifts
overall coverage to 56 percent.

### Added

- Unit tests for the clusterinfo, crd, events, geo, imageaudit, ingress,
  metrics, nodehealth, quota, resources, workload-coverage, and
  workload-security scanners. Every scanner now has test coverage.

### Removed

- Stale duplicate OpenAPI spec under deploy/openapi. The embedded
  internal/server/openapi.yaml served at /openapi.yaml is now the single
  source of truth.

## [0.1.1] - 2026-07-07

Hardening release. No behavior changes to scanning or the API. Adds automated
test coverage for the cluster-connection layer and five previously untested
scanners, wires up continuous integration, and fixes a context-ordering bug.

### Added

- Continuous integration workflow running gofmt, vet, build, and the
  race-enabled unit suite on every push and pull request, plus a kind-based
  integration job that exercises every scanner against live clusters.
- Unit tests for the `kube` connection layer and the `certs`, `admission`,
  `network-policies`, `rbac-audit`, and `deprecated-apis` scanners, all
  previously at zero coverage. A shared `testcerts` helper generates
  certificate fixtures with controlled expiry.

### Fixed

- `AvailableContexts` now returns kubeconfig context names in sorted order, as
  its documentation stated. Enumeration was previously in random map order.
- The `certs`, `admission`, `rbac-audit`, and `deprecated-apis` scanners now
  run against real clusters in the integration suite.
- Fixture-generating tests skip cleanly instead of failing when their output
  directory is not writable.

## [0.1.0] - 2026-07-06

Initial public preview. Twenty-four scanners, MAD-based outlier detection,
OLS regression with t-statistic gating for trends, SQLite and Postgres
history, cluster groups, 3D globe view, demo mode, Helm chart,
least-privilege RBAC, ClusterScan operator, and admission webhook.

### Added

- **Admission webhook certificate rotation.** Generated serving certs are
  now issued from an internal ten-year CA and reissued automatically
  before expiry, so the caBundle patched into the
  ValidatingWebhookConfiguration is stable and the webhook no longer
  breaks after 365 days. File-backed certs (`--admission-cert` /
  `--admission-key`) reload from disk when the files change, so
  cert-manager secret rotation needs no restart.
- **Watch-based controller.** The ClusterScan controller now runs a
  shared informer with a workqueue and a small worker pool. New or
  edited resources reconcile immediately from watch events instead of
  waiting for the next poll, the periodic due-scan check reads the
  informer cache instead of listing the API server, and one slow scan
  no longer blocks reconciliation of other resources.
- **Dashboard tag chips on the Clusters page.** Each cluster card now
  renders its tag map as small accent-colored chips
  (`env=prod`, `tier=critical`) right above the first-seen
  timestamp. Reads `ClusterRecord.tags` straight from the
  `/api/clusters` payload. No extra fetches.
- **`GET /api/clusters` now inlines tags.** Each `ClusterRecord`
  carries the cluster's tag map as `tags` (omitted when empty) so the
  dashboard's Clusters page can render tag chips without a follow-up
  `/api/tags` fetch. One extra store call per request rather than one
  extra fetch per row.
- **`fleetsweeper tag`** subcommand with `list`, `set`, and `del`
  variants. `fleetsweeper tag set prod-east env=prod tier=critical`
  upserts multiple pairs in one call. `fleetsweeper tag list` prints
  every cluster's tags in a deterministic table. Backed by the
  Phase 37 `cluster_tags` table. Pairs cleanly with the `?tag=`
  filters from Phase 38 for "tag in CLI, slice in dashboard"
  workflows.
- **Tag-aware report and alerts filters.** `GET
  /api/scans/{id}/report` and `GET /api/alerts` now accept repeating
  `?tag=key=value` query parameters. Repeated tags AND together, so
  `?tag=env=prod&tag=tier=critical` returns only findings (or alerts)
  on clusters carrying both tags. Fleet-wide findings (cluster=""
  or "fleet") and alerts with no cluster label pass through untouched.
  Tag filtering only narrows the per-cluster rows. Powers "drift
  in production only" dashboards without a parallel groups system.
- **Cluster tags.** New `cluster_tags` table (migration v7, both
  backends) with `(cluster, key)` primary key and indexes on
  `(key, value)`. Four endpoints: `PUT
  /api/clusters/{name}/tags/{key}` upserts, `DELETE` removes,
  `GET /api/clusters/{name}/tags` returns one cluster's map, and
  `GET /api/tags` returns every cluster's tags grouped by name (the
  shape the dashboard renders without an N+1 fetch). Cluster-scope
  enforcement applies on every endpoint so a scoped viewer can't see
  or modify tags on clusters outside its actor scope. Conventional
  keys: `env=prod`, `tier=critical`, `owner=team-a`.
- **Cinematic explainer.** Browser-rendered SVG cinematic at
  `/cinematic` walks the Fleetsweeper story across ten scenes (~95s
  total): fleet of clusters, drift table, statistical outlier
  detection, fleet score, admission webhook advisory mode, alerts
  ingest from four sources, leverage-ranked recommend list,
  whatchanged scan diff, in-cluster topology, and the closing CTA.
  ES5, no frameworks, no build step. YouTube-style scrubber with
  scene markers and hover tooltip. Respects
  `prefers-reduced-motion`. Pauses on `document.hidden`. Sidebar
  has a "Watch the cinematic" link next to How it works.
- **`fleetsweeper_policy_results_total{source, result}`** gauge.
  Aggregates the new policy-reports scanner's per-source tallies
  across the fleet (kyverno/gatekeeper/trivy/kube-bench) into a
  single Prometheus surface so Grafana can chart pass/fail/warn
  rates without re-parsing the report JSON. Documented in
  `deploy/grafana/README.md`.
- **OpenAPI coverage for alerts, webhooks, and timeline.** The
  bundled `openapi.yaml` now documents `GET /api/alerts`,
  `POST /api/alerts/{fingerprint}/ack`, the AlertManager + Falco
  inbound webhooks, and `GET /api/clusters/{name}/timeline`, plus a
  new `AlertRecord` schema. A startup test (`TestOpenAPISpec_ValidYAML`)
  parses the embedded spec and asserts the new paths are present so
  future drift is caught at `go test` time, not by SDK consumers.
- **Alert acknowledgements.** New `POST /api/alerts/{fingerprint}/ack`
  endpoint records an ack against an inbound alert. The handler
  fetches the alert row (new `Store.GetAlert` method) so the cluster,
  title, and `alert:<source>` scanner tag are server-derived. The
  client only supplies the optional reason, ack-by, and snooze. Same
  `finding_acks` table powers both scan-finding acks and alert acks
  so the dashboard surfaces them uniformly. The Alerts page now
  carries an Ack button that prompts for a reason and calls the new
  endpoint inline.
- **Dashboard Alerts page.** New sidebar entry next to Findings that
  surfaces the most recent inbound alerts via `/api/alerts`, with
  source (AlertManager / Falco) and severity filters. Double-click a
  row to inspect the full label set. Live mode (existing 30s poll)
  picks up new alerts without a manual refresh. The SSE bus
  (`alert.received`) already broadcasts ingest events, so the page
  stays current on long-lived sessions.
- **`fleetsweeper doctor --in-cluster`** mode. Extends the existing
  preflight with three checks against a deployed Helm release:
  `leader-lease` reads the coordination.k8s.io Lease and reports the
  current holder (warn when missing, fail when unreadable);
  `admission-webhook` confirms the ValidatingWebhookConfiguration
  exists with a CA bundle or Service reference; `scan-freshness`
  reads the latest scan from `--db` and flags it as stale when older
  than `--scan-freshness` (default 24h). The intended usage is
  immediately after `helm install`. Operators get a single
  pass/fail grid that proves the chart is actually doing work without
  having to poke around the dashboard.
- **`GET /api/clusters/{name}/timeline`** endpoint. Returns a
  chronological interleave of scans, ingested alerts (AlertManager +
  Falco), and acks for a single cluster, newest first. The dashboard
  uses this to answer "what's happened to this cluster recently"
  without the user pivoting between three different views. Scoped by
  the calling actor's cluster scope so a viewer with a single-cluster
  token can't browse other clusters' history.
- **Bundled Grafana dashboards.** Two new dashboards under
  `deploy/grafana/`: `drift-trends.json` (fleet score over time,
  findings volume, outlier z-scores, scan duration) and
  `alerts.json` (AlertManager + Falco ingest counters, ingest rate,
  cumulative by source). The README's installation section now
  documents both the manual upload flow and the Grafana sidecar
  ConfigMap recipe for kube-prometheus-stack deployments. A new
  `fleetsweeper_alerts_received_total{source}` counter powers the
  alerts dashboard.
- **`fleetsweeper recommend`** subcommand. Synthesises a prioritized
  action list from the latest scan: collapses identical remediations
  across clusters, scores each by `leverage * severity`, and surfaces
  the actual `kubectl` invocation or YAML snippet to apply. The hero
  metric is "this fix takes ten clusters from drifted to clean" —
  the command that highest-leverage operators can run before the
  next deploy. Supports `--severity` filtering, `--limit`, and
  `--json` output. Pairs naturally with `whatchanged` for a
  post-deploy review loop.
- **PolicyReport ingest scanner** (`policy-reports`). Reads
  `wgpolicyk8s.io/v1alpha2 PolicyReport` and `ClusterPolicyReport`
  resources produced by other policy tools (Kyverno, Gatekeeper,
  Trivy, kube-bench) and aggregates their fail/warn results per
  cluster. Breaks counts down by `source` so the dashboard can show
  "Kyverno: 14 failing, Gatekeeper: 3 failing, Trivy: 89 warning" in
  one rollup, and surfaces a worst-N list of policies for triage.
  Combined with Fleetsweeper's existing PolicyReport emission, this
  closes the loop: every policy tool in the fleet contributes to one
  unified findings stream.
- **`fleetsweeper whatchanged`** subcommand. Diffs two scans (or the
  latest two, when no IDs are given) and prints only what moved: new
  findings, cleared findings, fleet score delta, and per-cluster
  score regressions sorted worst-first. `--severity warning` clips
  the diff to actionable issues so deploy gates aren't drowned in
  info-level churn. Output is human-readable by default and `--json`
  for CI.
- **Falco runtime alert ingest.** A new
  `POST /api/webhooks/falco` endpoint accepts Falco HTTP_OUTPUT
  events (or events forwarded by falcosidekick) and persists them
  into the same `alerts` table used by the AlertManager receiver,
  tagged with `source=falco` in the labels map. Repeat firings of
  the same rule against the same pod/container fold onto a single
  row via a SHA-256 fingerprint of (cluster, rule, pod, container).
  Cluster identity is taken from the event's `cluster` /
  `k8s_cluster_name` field when present, otherwise from a
  `X-Fleetsweeper-Cluster` request header so falcosidekick deploys
  without customfields still get cluster-scoped routing. Bearer
  authentication via `--webhook-secret` matches the existing inbound
  webhooks.
- **`fleetsweeper export-metrics <dir>`** subcommand. Writes a
  `fleetsweeper.prom` file in the Prometheus textfile-collector
  exposition format (atomic via `.tmp` rename) so node_exporter's
  `--collector.textfile.directory` picks up `fleetsweeper_fleet_score`,
  `fleetsweeper_findings_total{severity=...}`, per-cluster scores, and
  the outlier set without running the HTTP server. Designed for edge
  deployments where the dashboard is a node_exporter Prometheus target
  and Fleetsweeper itself runs as a cron-style scan rather than a
  long-lived process.
- **`fleetsweeper drift`** subcommand. Lists every pod in a kubeconfig
  context (optionally narrowed to a single namespace) and applies the
  admission baseline checks locally so teams can gate CI without
  running the validating admission webhook in-cluster. The baseline is
  pulled from `--db` by default or from a pinned YAML via `--baseline`.
  Emits human-readable output by default and `--json` for machine
  consumers. `--fail-on-drift` flips the exit code when any pod
  deviates from the fleet norm, so dropping the command into a
  GitHub Action protects production from a manifest that snuck through
  review.
- **AlertManager webhook receiver.** A new `POST /api/webhooks/alertmanager`
  endpoint accepts Prometheus AlertManager v4 webhook payloads, persists
  every alert in a new `alerts` table keyed by AlertManager fingerprint,
  and emits an `alert.received` event on the SSE bus. `GET /api/alerts`
  returns the stored set with optional `cluster`, `status`, `severity`,
  `since`, and `limit` filters. The endpoint authenticates inbound
  requests with the shared `--webhook-secret` as a bearer token so the
  AlertManager `http_config.bearer_token` option drops in without
  additional plumbing. Alerts with no `cluster` label flow through to
  admins and operators only; viewers see only alerts within their
  cluster scope. Migration `v6` adds the `alerts` table to both the
  SQLite and Postgres backends.
- **`fleetsweeper baseline`** subcommand. Inspects, exports, and diffs the
  admission baseline derived from the most recent stored scan. `baseline
  show` prints the fleet-norm fractions as YAML; `baseline export <path>`
  pins them to a file; `baseline diff <path>` compares a pinned baseline
  against the current state and exits non-zero when any fraction drifts
  beyond `--epsilon` (default `0.05`, i.e. five percentage points). The
  diff path is wired for CI gating, so an unexpected drop in
  `digest_pin_fraction` or `non_root_fraction` fails the pipeline before
  the admission webhook starts denying real workloads.

### Fixed

- Docs now state the actual scanner count (24, not 16) and list every
  registered scanner in the concepts table.
- American spelling throughout code comments, CLI output, and docs.

- Admission baseline now reads the `workload-security` scanner key
  correctly. The previous key (`workload-sec`) silently zeroed the
  non-root, no-privilege-escalation, read-only-root-fs, and named-SA
  fractions in production, so the corresponding admission checks could
  never fire.

- **Per-actor token-bucket rate limiting.** New flags
  `--rate-limit-read-rpm` and `--rate-limit-write-rpm` impose
  per-actor budgets (per remote-address for anonymous traffic). Exceeded
  requests get `429 Too Many Requests` with a `Retry-After` header; the
  `X-RateLimit-Remaining` header advertises the current bucket level so
  well-behaved clients can self-throttle. Zero (default) disables.
- **Admission webhook check expansion**: `named-service-account` flags
  pods using the namespace default ServiceAccount when most of the fleet
  uses named SAs. `read-only-root-fs` flags containers whose root
  filesystem is writable when the fleet norm is read-only. Both fire only
  above the 70% baseline threshold and respect the configured advisory /
  enforce mode.
- **`fleetsweeper migrate`** subcommand. Copies every row from a source
  backend (`--from`) to a destination backend (`--to`) using the Store
  interface, so SQLite ↔ Postgres transitions no longer require manual
  pg_dump/sqlite3 .dump translation. Refuses non-empty destinations
  unless `--force` is passed; verifies row counts after copy when
  `--verify` is set (default).
- **`fleetsweeper doctor`** preflight subcommand. Runs database
  connectivity, kubeconfig parsing, per-context reachability, CRD
  presence, and (when `--addr` is set) HTTP `/healthz` + `/readyz` probes.
  Emits a color-friendly table by default or JSON with `--json` for
  monitors. Returns non-zero on any failure so it can gate CI/CD pipelines.
- **Trivy Operator vulnerability integration.** A new `vulnerabilities`
  scanner reads `aquasecurity.github.io/v1alpha1 VulnerabilityReport`
  resources via the dynamic client and aggregates critical/high/medium/low
  counts plus a top-20 worst-images list. Clusters with elevated CVE
  totals automatically light up as outliers via the existing MAD pipeline.
  Returns `available=false` (not an error) when Trivy isn't installed in
  a given cluster, so mixed fleets work fine.
- **Private registry probing for `image-audit`** via
  `--probe-registries`. Resolves manifests with auth derived from pod
  `imagePullSecrets`, ServiceAccount pull secrets, and the default
  keychain (ECR/GCR/ACR/GHCR helpers). Adds `images_probed`,
  `images_failed`, `oldest_image_age_days`, `avg_image_age_days` to the
  scanner output. Results cached in-process for five minutes.
- **End-to-end operator kind test** (`-tags=integration`) provisions a
  kind cluster, applies the ClusterScan CRD, runs the in-process
  controller, and verifies the reconciler drives a resource to
  `phase=Succeeded`.
- **Multi-tenant API keys with roles and cluster scoping.** New tables
  `api_keys` and `audit_log` (migration v5). Roles: `admin`, `operator`,
  `viewer`. Scope is `*`, a list of cluster names, or `group:<name>` entries.
  Mutating endpoints now resolve the calling actor and refuse out-of-scope
  cluster operations. Bearer tokens are stored as SHA-256 hashes; the raw
  token is shown exactly once at creation.
- **Audit log.** Every mutating request is recorded with actor identity,
  method, path, status, duration, and a short error excerpt. Admin keys can
  query it at `GET /api/admin/audit` with filters (`since`, `actor`,
  `min_status`).
- **Admin endpoints** for key lifecycle:
  `POST /api/admin/keys`, `GET /api/admin/keys`, `DELETE /api/admin/keys/{id}`,
  `GET /api/admin/whoami`, `GET /api/admin/audit`.
- **CLI: `fleetsweeper apikey {create,list,revoke}`** for offline key
  management against the configured database, so the first admin key can be
  minted before the server is reachable.
- **ClusterScan CRD (`fleetsweeper.io/v1alpha1`) + reconciler.** Declarative
  scan definitions watched by an in-process controller enabled via
  `serve --controller`. Status is written back to the resource so
  `kubectl get clusterscan` shows phase, score, grade, finding counts,
  last/next scan times. CRDs ship in `deploy/crds/` and as Helm templates
  (`values.crds.install`); RBAC is extended to grant the controller
  `get/list/watch/update/patch` on ClusterScan and its `/status` subresource.
- `VERSIONING.md` and `UPGRADING.md` documenting the stability contract and
  per-release migration steps.
- **PostgreSQL backend** behind the same `Store` interface as SQLite. New
  flag `--db-driver` (sqlite/postgres, auto-detected from DSN prefix when
  empty); the existing `--db` accepts a `postgres://...` DSN. Helm chart
  exposes `database.driver=postgres` which wires the DSN in via Secret.
  Migration numbers are aligned across backends, so the same migration
  history is recorded whichever driver writes it.
- **Leader election** via `coordination.k8s.io/v1` Leases. The scheduler
  and ClusterScan reconciler now run on whichever replica holds the lease,
  so multi-replica deployments with a shared Postgres no longer double-fire
  side effects. New flags `--leader-election` (default `true` in-cluster),
  `--leader-namespace` (defaults to `$POD_NAMESPACE`), and `--leader-name`.
  Helm chart adds a namespaced Role + RoleBinding granting the
  ServiceAccount lease permissions in the release namespace.
- **Operational Helm templates**: PodDisruptionBudget, ServiceMonitor
  (Prometheus Operator), and NetworkPolicy (default-deny ingress + targeted
  egress) all gated by `values.*.enabled`. Plus a post-install
  `NOTES.txt` walking new operators through port-forwarding the dashboard,
  minting their first scoped key, and enabling the controller.
- **`fleetsweeper backup` / `fleetsweeper restore`** subcommands. Uses
  SQLite's online `VACUUM INTO` for a consistent snapshot, with optional
  gzip compression and a restore path that opens + migrates the target
  before returning so operators discover schema mismatches at restore time,
  not at first request.
- **krew plugin manifest** at `deploy/krew/plugin.yaml` for the kubectl
  plugin index, so users can `kubectl krew install fleetsweeper` once the
  manifest is upstreamed.
- **`/api/admin/system` endpoint** plus **`fleetsweeper serve --config FILE`**
  YAML config support. The endpoint returns version, build info, uptime,
  storage backend health, feature toggles, and lifetime scan counters. The
  config file accepts the same flag names CLI uses; CLI flags still win when
  present. An example lives at `deploy/examples/serve-config.yaml`.
- **Audit log retention** via `--audit-retention <duration>`. An hourly
  ticker prunes `audit_log` rows older than the configured window. Empty or
  zero disables retention (preserves existing behavior).
- **Controller metrics** in the Prometheus exposition:
  `fleetsweeper_controller_reconcile_total`,
  `fleetsweeper_controller_reconcile_outcome_total{outcome=...}`,
  `fleetsweeper_controller_scans_total{result=...}`,
  `fleetsweeper_controller_paused_resources`. The dashboard can graph the
  declarative-scan workload alongside the existing per-cluster metrics.
- **`fleetsweeper init [path]`** scaffolds a starter deployment folder with
  Helm overrides, a sample ClusterScan, an optional serve-config.yaml, and
  a README walking new operators through the first install. The bootstrap
  token is generated fresh per scaffold so users do not have to invent one.
- **Server-Sent Events stream at `/api/events`** fanning out
  `scan.complete`, `scan.failed`, and `key.revoked` events. The dashboard
  reacts to scan completion without polling, and external consumers can
  subscribe with one connection per consumer. Backpressure-tolerant:
  buffered fan-out with drop-on-overflow per subscriber.
- **OIDC browser login** via the OAuth2 Authorization Code flow. Endpoints
  `/oidc/login`, `/oidc/callback`, `/oidc/logout` complete the dance with
  the configured IdP (Google, Okta, Keycloak, Dex, Auth0, ...). The session
  is carried in a signed HMAC-SHA256 cookie that is HttpOnly, Secure on
  TLS, and stateless so multi-replica deployments need no sticky sessions.
  Role is derived from configurable claim mappings
  (`--oidc-admin-claim`/`--oidc-operator-claim`, default falls through to
  viewer). Bearer-token API auth continues to work unchanged. New Helm
  values under `oidc.*` wire client-secret + session-secret via a generated
  or pre-existing Secret.
- **ValidatingAdmissionWebhook** (`/admission/validate`) that compares pods
  to the fleet baseline derived from the most recent scan. Advisory mode
  (default) emits Kubernetes admission warnings; enforce mode denies pods
  that deviate from the fleet norm. Self-signed TLS cert generated at
  startup, or pass `--admission-cert`/`--admission-key` for cert-manager.
  Built-in checks: `digest-pin`, `non-root`, `no-privilege-escalation`.
  New Helm values under `admission.*`; ValidatingWebhookConfiguration +
  Service templates ship with the chart. New `--admission-addr`,
  `--admission-mode`, `--admission-cert`, `--admission-key`,
  `--admission-dns` serve flags.
- OpenTelemetry tracing for scans (one span per scanner per cluster) and
  OTel metrics export (Fleet Score, findings, per-cluster health, scan
  duration), both wired up automatically when `OTEL_EXPORTER_OTLP_ENDPOINT`
  is set.
- wgpolicyk8s.io PolicyReport export via `--policy-report-output`. One file
  per cluster in the CNCF-standard format that Kyverno, Trivy Operator, and
  Policy Reporter UI already understand.
- FleetDriftReport CRD and per-cluster YAML emission via
  `--fleetdrift-output` for native GitOps workflows.
- `fleetsweeper remediate` subcommand opens a pull request against a GitOps
  repo via the GitHub REST API for findings with inline YAML remediation.
  Default is dry-run; `--push` actually creates the PR.
- Per-cluster forecast endpoint `/api/forecast/clusters` ranks clusters by
  projected trajectory.
- Cost correlation: provide a CSV of cluster spend and `/api/cost` returns
  drift cost per cluster, no cloud SDK dependencies.
- Fleet Score: a single 0-100 indicator on the dashboard summarising fleet
  health, with a week-over-week delta. Computed from cluster health,
  finding severities, and version skew.
- Prometheus metrics endpoint on the admin server. Exposes per-cluster health
  status, finding counts by severity and scanner, scan durations, and outlier
  scores. See `deploy/grafana/fleet-overview.json` for a starter dashboard.
- Slack webhook notifier for critical findings. Posts new criticals with
  their parameterized `kubectl` remediation. Configured via
  `--slack-webhook-url` on `serve`.
- Keyboard shortcut overlay reachable with `?`. Documents Cmd-K palette,
  navigation chords, search, and tour controls.
- Grafana dashboard JSON at `deploy/grafana/fleet-overview.json`.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, GitHub issue and
  pull request templates.

### Changed

- Cinematic tour copy tightened to four-second dwells with motion-first
  steps. Body copy capped at twenty words per step.
- README adds a comparison table against neighbouring tools, a badge row,
  and a hero placeholder for an animated demo.
- `.gitignore` now covers SQLite WAL artifacts, IDE scratch, dist output,
  and OS detritus.

### Removed

- `demo.db` and SQLite WAL files are no longer tracked. They are created on
  demand in `:memory:` when `--demo` is used without `--db`.

