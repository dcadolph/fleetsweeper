# Webhooks

Fleetsweeper has two webhook surfaces: inbound (trigger a scan) and
outbound (notify subscribers when a scan completes). Both use the same
HMAC-SHA256 signing scheme.

## Inbound: trigger a scan

Enable by setting a shared secret:

```yaml
serve:
  args:
    - --webhook-secret=$WEBHOOK_SECRET
```

Then POST to `/api/webhooks/scan-trigger`:

```shell
BODY='{"all_contexts": true}'
SIG="sha256=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -binary | xxd -p -c 256)"
curl -X POST \
  -H "X-Fleetsweeper-Signature: $SIG" \
  -H 'Content-Type: application/json' \
  --data "$BODY" \
  https://fleetsweeper.example.com/api/webhooks/scan-trigger
```

Use the empty body to scan every available context.

The endpoint is **disabled** (returns 404) when the secret is empty so an
unsigned endpoint cannot be left exposed by mistake.

## Outbound: notify subscribers

Subscribe in a YAML file referenced via `--webhook-config`:

```yaml
subscribers:
  - url: https://internal.example.com/fleetsweeper-events
    secret: "subscriber-shared-secret"
    events:
      - scan.complete
      - finding.critical.new
  - url: https://internal.example.com/cost-alerts
    secret: "another-shared-secret"
    events:
      - cost.spike
```

Fleetsweeper posts a JSON envelope with the event type plus the relevant
payload (scan summary, finding fingerprint, cluster name) signed with the
subscriber's shared secret. Subscribers verify the signature and act on
the event.

## Signature format

`X-Fleetsweeper-Signature: sha256=<lowercase hex digest of HMAC-SHA256(secret, body)>`

This is the same format GitHub and Stripe use, so existing libraries verify
out of the box.
