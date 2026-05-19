<p align="center">
  <img src="internal/logo/logo.png" alt="fleetsweeper" width="260">
</p>

<h1 align="center">Fleetsweeper</h1>

<p align="center">
  <b>The cluster that drifted is the one that pages you at 3am.</b><br>
  Fleetsweeper finds it before it does.
</p>

<p align="center">
  <a href="https://github.com/dcadolph/fleetsweeper/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dcadolph/fleetsweeper/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/dcadolph/fleetsweeper/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/dcadolph/fleetsweeper?sort=semver"></a>
  <a href="https://pkg.go.dev/github.com/dcadolph/fleetsweeper"><img alt="Go reference" src="https://pkg.go.dev/badge/github.com/dcadolph/fleetsweeper.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

---

You run twelve clusters. Or fifty. Or two hundred. They started identical
and they did not stay that way. Versions skew. Admission policies drift.
Service accounts get patched at 3am and nobody writes it down. Every
cluster is "healthy" on its own, so every tool you already own stays
quiet. Fleetsweeper finds the one cluster that wandered off the herd.

The fleet itself is the baseline. No rulebook. No thresholds to tune.
The [modified z-score](https://en.wikipedia.org/wiki/Median_absolute_deviation)
across your own clusters does the work.

### What you walk away with after one scan

- A **Fleet Score** from 0 to 100 with a one-line headline you can put on a status TV.
- The cluster that is most unlike the rest, plus the exact fields that flagged it.
- **Ranked, leverage-weighted recommendations**. The fix that takes ten clusters from drifted to clean ranks ahead of the same fix on one.
- An optional **admission webhook** that denies pods deviating from your fleet's actual norm, not from a static checklist.
- One unified stream for inbound signal: scan findings, AlertManager, Falco, Trivy CVEs, Kyverno and Gatekeeper [PolicyReports](https://github.com/kubernetes-sigs/wg-policy-prototypes).

## See it in 30 seconds

```
go install github.com/dcadolph/fleetsweeper@latest
fleetsweeper serve --demo --addr :8080
```

Open `http://localhost:8080`. A synthetic 26-cluster fleet renders across
four continents with a 3D globe, findings, trends, outliers, capacity, and
a guided tour. No kubeconfig required. The pulsing red dots are the
cinematic part. The outlier detection under them is the real part.

## Install for real

```
helm install fleetsweeper deploy/helm/fleetsweeper \
  --set auth.token=$(openssl rand -hex 32) \
  --set controller.enabled=true
kubectl apply -f deploy/examples/clusterscan-prod.yaml
```

The controller reconciles `ClusterScan` resources and writes outcomes back
to `.status`. Full installation paths in
[`docs/operator/helm.md`](docs/operator/helm.md). Scoped API keys for
pipelines in [`docs/operator/rbac.md`](docs/operator/rbac.md).

## Why this and not what you already have

| You already use            | What it tells you                                | What Fleetsweeper adds                                                              |
| -------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `kubectl`, k9s             | The state of one cluster, right now.             | A fleet-wide comparison across 16 dimensions. Names the outlier.                    |
| Argo CD, Flux              | Whether each cluster matches its manifest.       | Drift across clusters even when every cluster matches its own source of truth.      |
| Prometheus, Grafana        | Time series for what you remembered to instrument. | Statistical baselines derived from the fleet, with no rules to write.             |
| Datadog Cluster Insights   | Per-cluster alerts scored by a vendor rulebook.  | The norm is your own fleet, not a vendor checklist.                                 |
| OPA, Kyverno               | Violations against rules you authored.           | Detects drift you forgot to write a rule for. Complements, does not replace.        |

## Production-ready out of the box

HA backends, leader election, scoped RBAC, audit log, declarative CRDs,
Prometheus and OpenTelemetry, signed reports, backups, GitOps integrations,
admission webhook, and supply-chain signed images. Full checklist:
[`docs/production-readiness.md`](docs/production-readiness.md).

## Where to go next

**Start here**
- [Getting started](docs/getting-started.md). First scan, persistence, history, groups.
- [Architecture](docs/architecture.md). How the pipeline fits together.
- [Scanners](docs/concepts/scanners.md). The 16 dimensions Fleetsweeper checks.

**Concepts**
- [The fleet is the policy](docs/concepts/fleet-is-policy.md). Why norm-based detection scales.
- [Fleet Score](docs/concepts/fleet-score.md). What the number means.
- [Outliers](docs/concepts/outliers.md). MAD-based statistical detection.
- [Findings and remediation](docs/concepts/findings.md). Severity calibration and `kubectl` outputs.
- [Globe view](docs/concepts/globe.md). Geolocation sources and overrides.

**Operator**
- [Overview](docs/operator/overview.md), [Helm](docs/operator/helm.md), [Server mode](docs/operator/server-mode.md)
- [ClusterScan CRD](docs/operator/clusterscan.md), [Leader election](docs/operator/leader-election.md), [Backends](docs/operator/backends.md)
- [RBAC and API keys](docs/operator/rbac.md), [Audit log](docs/operator/audit.md), [OIDC](docs/operator/oidc.md)
- [Admission webhook](docs/operator/admission-webhook.md), [Recommend](docs/operator/recommend.md), [What changed](docs/operator/whatchanged.md)

**Integrations**
- [Prometheus](docs/integrations/prometheus.md), [Slack](docs/integrations/slack.md), [Webhooks](docs/integrations/webhooks.md)
- [PolicyReport](docs/integrations/policyreport.md), [FleetDriftReport](docs/integrations/fleetdriftreport.md)
- [AlertManager](docs/integrations/alertmanager.md), [Falco](docs/integrations/falco.md), [Trivy](docs/integrations/trivy.md)
- [GitHub Actions](docs/integrations/github-actions.md), [Registry probing](docs/integrations/registry-probing.md)

**Reference**
- [CLI](docs/reference/cli.md), [API](docs/reference/api.md), [Events](docs/reference/events.md)
- [Versioning](docs/reference/versioning.md), [Upgrading](docs/reference/upgrading.md), [Doctor](docs/reference/doctor.md)

## Contributing

Issues and PRs welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). Security disclosures go through
[`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
