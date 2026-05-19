# Falco

Fleetsweeper accepts Falco HTTP_OUTPUT events so runtime security
detections show up next to drift findings and Prometheus alerts on the
dashboard. Falco rule firings land in the same `alerts` table the
AlertManager receiver uses, tagged with `source=falco` in the
labels map.

## Endpoint

```
POST /api/webhooks/falco
Authorization: Bearer <fleetsweeper-webhook-secret>
Content-Type: application/json
X-Fleetsweeper-Cluster: <cluster-name>   # optional; see below
```

The shared `--webhook-secret` is reused as the bearer token. The
endpoint returns 404 when no secret is configured so the receiver is
never silently exposed.

## Falco / falcosidekick configuration

The recommended setup is Falco + falcosidekick. Falco itself can send
events directly via `http_output`, but falcosidekick adds retries,
buffering, and `customfields` for cluster tagging.

### falcosidekick

```yaml
webhook:
  address: https://fleetsweeper.example.internal/api/webhooks/falco
  customheaders: |
    Authorization: Bearer ${FLEETSWEEPER_WEBHOOK_SECRET}
    X-Fleetsweeper-Cluster: prod-east
  minimumpriority: notice
```

### Falco directly

```yaml
http_output:
  enabled: true
  url: https://fleetsweeper.example.internal/api/webhooks/falco
  user_agent: "falco/0.x"
  insecure: false
```

Falco's http_output does not support custom headers, so either:

- Add `cluster: <name>` to the rule outputs via `customfields`, or
- Front Falco with a tiny webhook relay that adds the
  `Authorization` and `X-Fleetsweeper-Cluster` headers, or
- Switch to falcosidekick (recommended).

## Deduplication

Falco fires the same rule repeatedly when an offending process keeps
running. Fleetsweeper computes a SHA-256 fingerprint of
`(cluster, rule, pod, container_id)` and uses it as the alerts table
primary key. The result: the dashboard shows one row per unique
runtime incident, refreshed with each new firing rather than buried
under duplicates.

If you need every individual firing instead (forensic mode), forward
the events to an audit pipeline directly. Fleetsweeper's alerts
table is intended as a "what's broken right now" view.

## Querying

Falco rows are returned by the same `GET /api/alerts` endpoint:

```
GET /api/alerts?cluster=prod-east&severity=critical
```

To filter only Falco events client-side, look for
`labels.source == "falco"`. The original Falco `output_fields` are
preserved verbatim in `labels` (non-string values are
JSON-stringified), so MITRE tags, executable names, and file paths
survive the round-trip.

## SSE events

Falco firings emit the same `alert.received` SSE event as
AlertManager. The dashboard cannot tell them apart at fan-out time.
Consumers that need source-specific routing should fetch the full
record via `GET /alerts` after receiving the event.
