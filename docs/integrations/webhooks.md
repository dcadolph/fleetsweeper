# Webhooks

Fleetsweeper has two webhook surfaces: inbound (trigger a scan, signed with
HMAC-SHA256) and outbound (send findings to subscribers after each scan,
authenticated with headers you configure).

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

Subscribe in a YAML file referenced via `--webhook-config`. A complete example
lives in `deploy/examples/webhooks.yaml`:

```yaml
webhooks:
  - name: oncall
    url: https://hooks.example.internal/fleetsweeper
    min_severity: critical
    cluster_regex: "^prod-"
    headers:
      Authorization: "Bearer $ONCALL_HOOK_TOKEN"
  - name: platform-chat
    url: https://chat.example.internal/hooks/platform
    min_severity: warning
    scanner_regex: "^(certs|admission)$"
    body_template: |
      {"text": "{{ .Severity }} on {{ .Cluster }}: {{ .Title }}"}
```

After every scan, each finding at or above a subscriber's `min_severity`
(default `info`) whose scanner and cluster match its optional regexes is
POSTed to its `url`, one request per finding. A finding already sent to a
subscriber in the last six hours is not sent again. Without a
`body_template` the body is a JSON object with `severity`, `cluster`,
`scanner`, `title`, `description`, `affected`, and `remediation`. A template
is Go `text/template` over the same fields, capitalized, plus `.Env`.
Header values and rendered bodies expand `$VARS` from the server's
environment, so tokens stay out of the file. `content_type` defaults to
`application/json`. Outbound requests are not signed: authenticate them with
a header. A failed delivery is logged and never fails the scan.

## Inbound signature format

`X-Fleetsweeper-Signature: sha256=<lowercase hex digest of HMAC-SHA256(secret, body)>`

This is the same format GitHub and Stripe use, so existing libraries verify
out of the box.
