# Contributing to Fleetsweeper

Thanks for wanting to make Fleetsweeper better. This document describes how to
get a local build going, the conventions the project follows, and how to land
a change.

## Getting set up

You need Go (version pinned in `go.mod`) and, if you want to run the
integration tests, Docker and [kind](https://kind.sigs.k8s.io/).

```
git clone https://github.com/dcadolph/fleetsweeper.git
cd fleetsweeper
go build ./...
go test -race ./...
```

The binary builds to `./fleetsweeper`. Try the demo dashboard with no real
clusters required:

```
./fleetsweeper serve --demo --addr :8080
```

## Project layout

- `cmd/` -- the Cobra CLI surface. One file per top-level command.
- `internal/scanner/` -- per-scanner packages. Each one implements a single
  `Scan(ctx, *kube.Client) (Result, error)` method.
- `internal/report/` -- comparison engine, severity calibration, outlier
  detection, trend regression, finding generation.
- `internal/server/` -- HTTP API, web UI, demo mode, geo handlers, middleware.
- `internal/store/` -- SQLite persistence.
- `deploy/` -- Helm chart, RBAC, example ConfigMaps and namespace annotations.

## Conventions

### Code style

- Standard Go style. `gofmt`, `go vet`, and `golangci-lint run` must all pass.
- 100 character soft line limit. Function signatures may go to 120.
- Every exported function, method, struct, struct field, and interface gets a
  doc comment that starts with the identifier name.
- Imports grouped in three blocks: standard library, third-party, internal.
- No unnecessary abstractions or backwards-compatibility shims. The project
  has no production users yet, so refactor freely.

### Adding a scanner

A scanner lives in `internal/scanner/<name>/<name>.go` and implements the
`scanner.Scanner` interface. Register it in `cmd/cmd_scan.go` and
`cmd/cmd_serve.go` so it joins the default registry. Severity classification
goes in `internal/report/severity.go`. Findings and remediation hints go in
`internal/report/findings.go`.

If your scanner reports a numeric value that could vary across clouds, list
the field in `warningFields` rather than `criticalFields`. Save `critical` for
genuinely page-worthy conditions.

### Tests

- Table-driven, parallel, no third-party assertion libraries.
- Use `cmp.Diff` with `cmpopts.EquateEmpty()` and `errors.Is` for comparisons.
- Test the happy path, every error path, and edge cases (nil, empty, boundary
  values).
- Integration tests that need a real cluster live under
  `internal/integration/` with the `//go:build integration` tag.

### Commit messages

Short, imperative, under 72 characters in the subject. Body text optional.
Examples that follow the existing log:

```
Add Slack webhook sink for critical findings
Fix MAD divide-by-zero on uniform integer fields
Tighten dashboard hero copy
```

### Pull requests

- Open against `main`.
- Keep the change focused. A reviewer should not need a roadmap to follow it.
- Run `go test ./...` and `golangci-lint run` before pushing.
- Mention the user-visible impact in the description, not just the mechanics.

## Reporting bugs

Open an issue using the bug report template. Include:

- Fleetsweeper version (`fleetsweeper --version`).
- A minimal command that reproduces the bug.
- Expected vs actual output. Logs from `--log-level debug` help a lot.

For security issues see [SECURITY.md](SECURITY.md).

## Suggesting features

Open an issue with the feature request template. Tell the maintainers what
problem you are trying to solve before proposing a specific implementation.
Sometimes the right answer is a smaller change in a different place.

## Code of conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).
