# Slack

Fleetsweeper can post new critical findings to a Slack channel via an
incoming-webhook URL.

## Enable

```yaml
serve:
  args:
    - --slack-webhook-url=$SLACK_WEBHOOK_URL
```

Or via Helm:

```yaml
slack:
  webhookURL: https://hooks.slack.com/services/...
```

## Behaviour

- Only **new** critical findings post. A fingerprint of each posted finding
  is remembered so a recurring scan does not re-notify on unchanged
  criticals.
- The post includes the cluster, scanner, title, and the parameterised
  `kubectl` remediation when the finding ships with one.
- Failures to post are logged at warn level and never fail the scan.

## Per-ClusterScan opt-in

When the controller is enabled, set `spec.emit.slack: true` on each
ClusterScan to control which scans deliver to Slack. Scans without the
flag set will skip Slack entirely.
