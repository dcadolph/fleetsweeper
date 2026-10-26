package report

import "errors"

// ErrBuild indicates a failure building the comparison report.
var ErrBuild = errors.New("build report")

// ErrWhatIf indicates a what-if fix that does not apply to the scan.
var ErrWhatIf = errors.New("what-if")
