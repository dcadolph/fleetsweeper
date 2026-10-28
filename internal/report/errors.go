package report

import "errors"

// ErrWhatIf indicates a what-if fix that does not apply to the scan.
var ErrWhatIf = errors.New("what-if")
