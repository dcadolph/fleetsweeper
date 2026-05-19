<!-- Thanks for the patch. Please fill in the sections below. Delete any that
do not apply. -->

## Summary

<!-- One or two sentences. What does this change, and why. Focus on the
user-visible impact, not the mechanics. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New scanner
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Build / CI / tooling
- [ ] Breaking change (describe migration below)

## How I tested this

<!-- Commands you ran and what you observed. If the change touches the
dashboard, include a screenshot or a short clip. -->

```
go test ./...
golangci-lint run
```

## Checklist

- [ ] `go test ./...` passes.
- [ ] `go vet ./...` is clean.
- [ ] `golangci-lint run` is clean (or only flags pre-existing noise).
- [ ] New code has doc comments on exported and unexported declarations
      following the repo conventions.
- [ ] If user-visible, the README or CHANGELOG was updated.
- [ ] No new dependencies were added without justification in the PR body.

## Linked issues

<!-- Closes #123, refs #456. -->
