package scanner

import "errors"

// ErrScan indicates a scanner failed to collect data from a cluster.
var ErrScan = errors.New("scan failed")
