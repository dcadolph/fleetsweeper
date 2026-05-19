# GitHub Actions

Fleetsweeper ships four composite actions under `.github/actions/`
that drop into any GitHub workflow. They all download the released
binary on first run (cached in `~/.fleetsweeper/bin`) and shell out
to the corresponding subcommand.

| Action | Subcommand | Typical use |
| --- | --- | --- |
| `scan` | `fleetsweeper scan` | Periodic fleet sweep; fail on critical findings |
| `drift` | `fleetsweeper drift` | Pre-flight CI gate against a staging context |
| `whatchanged` | `fleetsweeper whatchanged` | Post-deploy verification: did this release move the score |
| `recommend` | `fleetsweeper recommend` | Render the prioritised action list; optionally post to PR |

Every action emits a job summary (the kbd line in the Actions UI) and
exposes structured outputs so downstream steps can branch.

## Periodic scan

```yaml
- uses: dcadolph/fleetsweeper/.github/actions/scan@main
  with:
    all-contexts: "true"
    fail-on: critical
```

Exit code is non-zero when one or more critical findings appear, so
the job fails and triggers your existing alert channels.

## PR-time drift audit

```yaml
- uses: dcadolph/fleetsweeper/.github/actions/drift@main
  with:
    context: staging
    baseline: ./baseline/fleet.yaml
    fail-on-drift: "true"
```

Pair this with a pinned baseline (`fleetsweeper baseline export`)
checked into the repo. Drift against the pinned norm blocks
promotion; drift against the live (auto-refreshing) baseline does
not.

## Post-deploy whatchanged

```yaml
- uses: dcadolph/fleetsweeper/.github/actions/whatchanged@main
  with:
    db: ${{ env.HOME }}/.fleetsweeper/fleet.db
    fail-on-new-critical: "true"
    fail-on-score-drop: "5"
```

Two gates:

- **`fail-on-new-critical`** — any new critical finding fails the job.
- **`fail-on-score-drop`** — the fleet score regressing by more than
  N points fails the job. Set to 0 to disable.

## PR comment with top recommendations

```yaml
- uses: dcadolph/fleetsweeper/.github/actions/recommend@main
  with:
    db: ${{ env.HOME }}/.fleetsweeper/fleet.db
    severity: warning
    limit: "5"
    pr-comment: "true"
```

Reads the latest scan, renders the top-N leverage-ranked fixes, and
posts them as a PR comment via `GITHUB_TOKEN`. Requires
`pull-requests: write` in the job's permissions block.

## Full example

The repo ships two example workflows under `.github/workflows/`:

- **`fleetsweeper-scan.example.yml`** — periodic fleet sweep on a cron.
- **`fleetsweeper-pr.example.yml`** — combined drift + whatchanged +
  recommend on every pull request.

Rename either file (drop the `.example`) into your own repo and
populate the secret references.
