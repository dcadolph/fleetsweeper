# Events stream

`GET /api/events` exposes a Server-Sent Events (SSE) stream that fans out
scan-complete and key-revoke events to anyone subscribed. The dashboard
uses it to refresh on scan completion without polling, and external
consumers can subscribe with one TCP connection per consumer.

## Event types

| Type | When it fires | Payload |
| --- | --- | --- |
| `stream.hello` | First event after the connection opens. | empty |
| `scan.complete` | After a scan persists (scheduled, triggered, or controller-driven). | `{ scan_id, clusters, score, grade }` |
| `scan.failed` | When a triggered scan errored out before persistence. | `{ reason }` |
| `key.revoked` | When an admin revokes an API key. | `{ key_id, revoked_by }` |

New types may be added in additive releases. Consumers should ignore types
they do not recognize.

## Wire format

```text
event: scan.complete
data: {"type":"scan.complete","at":"2026-05-17T12:00:00Z","payload":{"scan_id":"...","clusters":12,"score":88,"grade":"B"}}

```

Standard SSE. Every event has a `type:` line and a single JSON-encoded
`data:` line. A `:` keepalive comment fires every 30 seconds to keep
intermediate proxies from dropping the connection.

## Authentication

Same bearer auth as the rest of the API. The connection must include
`Authorization: Bearer <token>` when not in `--insecure` mode. Viewers,
operators, and admins can subscribe; only mutating endpoints require
write-capable roles.

## Backpressure

Each subscriber has a 16-event buffer. When the buffer fills, additional
events are dropped silently rather than blocking fan-out to other
subscribers. Slow consumers must keep draining the stream; missed events
can be recovered by re-fetching the scan record via the REST API.

## Browser example

```javascript
const es = new EventSource('/api/events', { withCredentials: true });
es.addEventListener('scan.complete', (ev) => {
  const { scan_id, score, grade } = JSON.parse(ev.data).payload;
  refreshDashboard(scan_id, score, grade);
});
es.addEventListener('key.revoked', (ev) => {
  console.warn('key revoked', JSON.parse(ev.data).payload);
});
```

## Shell example

```shell
curl -N -H "Authorization: Bearer $TOKEN" https://fleetsweeper/api/events
```
