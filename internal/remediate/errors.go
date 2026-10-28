package remediate

import "errors"

var (
	// ErrNoYAML is returned when the finding has no inline YAML remediation to push.
	ErrNoYAML = errors.New("finding has no inline YAML remediation, nothing to push")
	// ErrRepo is returned when the owner or repo is missing.
	ErrRepo = errors.New("owner and repo are required")
	// ErrToken is returned when pushing without a GitHub token.
	ErrToken = errors.New("github token required when pushing")
)
