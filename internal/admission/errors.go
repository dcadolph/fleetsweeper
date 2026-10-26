package admission

import "errors"

// ErrBaselineFile indicates a pinned baseline file could not be read or is invalid.
var ErrBaselineFile = errors.New("pinned baseline file")
