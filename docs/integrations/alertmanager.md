# AlertManager

Fleetsweeper accepts Prometheus AlertManager webhooks so the dashboard
can correlate live runtime alerts with the rest of the fleet picture
(drift, outliers, advisories). Every alert delivered to the endpoint is
persisted to the `alerts` table, fans out on the SSE bus as
`alert.received`, and is queryable through `GET /api/alerts`.

## Endpoint

```
POST /api/webhooks/alertmanager
Authorization: Bearer <fleetsweeper-webhook-secret>
Content-Type: application/json
```

The shared `--webhook-secret` is reused as the bearer token so the
AlertManager `http_config.bearer_token` option drops in directly. The
endpoint is disabled (404) when no secret is configured so an
unsigned receiver cannot be left exposed by accident.

## AlertManager configuration

```yaml
receivers:
  - name: fleetsweeper
    webhook_configs:
      - url: https://fleetsweeper.example.internal/api/webhooks/alertmanager
        send_resolved: true
        http_config:
          bearer_token: $FLEETSWEEPER_WEBHOOK_SECRET

route:
  receiver: fleetsweeper
  group_by: [alertname, cluster]
  routes:
    - matchers: [severity="critical"]
      receiver: fleetsweeper
```

`send_resolved: true` is recommended so Fleetsweeper can flip the row
status from `firing` to `resolved` when the alert clears. The same
fingerprint upserts in place; no rows are duplicated.

## Cluster correlation

Fleetsweeper reads the `cluster` label from each alert and stores it as
the `cluster` column. Make sure your Prometheus relabeling adds a
stable `cluster` label per workload. Without it, alerts land with an
empty cluster scope and are visible only to admins and operators
through the API.

## Querying

```
GET /api/alerts?cluster=prod-east&status=firing&severity=critical
GET /api/alerts?since=2026-05-18T00:00:00Z&limit=200
```

The response shape is:

```json
{
  "alerts": [
    {
      "fingerprint": "abc...",
      "cluster": "prod-east",
      "status": "firing",
      "alertname": "HighMemory",
      "severity": "critical",
      "summary": "Memory above 90% on prod-east kube-apiserver",
      "starts_at": "2026-05-18T19:31:00Z",
      "received_at": "2026-05-18T19:31:14Z",
      "labels": {...},
      "annotations": {...},
      "generator_url": "https://prom.example/graph?expr=..."
    }
  ],
  "count": 1
}
```

## SSE events

The endpoint emits one `alert.received` event per stored alert. The
payload is the minimum needed for the dashboard to badge a cluster
without a follow-up fetch:

```json
{
  "type": "alert.received",
  "at": "2026-05-18T19:31:14Z",
  "payload": {
    "fingerprint": "abc...",
    "cluster": "prod-east",
    "status": "firing",
    "alertname": "HighMemory",
    "severity": "critical"
  }
}
```

Full row details remain queryable through `GET /alerts`.

## Retention

Alerts are kept until pruned. Use the same retention policy you use
for `audit_log` rows. Alerts are append-mostly and the table grows
linearly with notification volume.
