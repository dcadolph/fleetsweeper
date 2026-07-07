package scanner

import (
	"context"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// Scanner collects cluster-specific data for a single scan dimension.
type Scanner interface {
	Scan(ctx context.Context, client *kube.Client) (Result, error)
}

// ScannerFunc adapts a plain function to the Scanner interface.
type ScannerFunc func(ctx context.Context, client *kube.Client) (Result, error)

// Scan calls the underlying function.
func (f ScannerFunc) Scan(ctx context.Context, client *kube.Client) (Result, error) {
	return f(ctx, client)
}

// State describes how much to trust a scanner's data for one cluster. It exists
// so an unreachable or forbidden API produces a degraded or errored result
// instead of an empty payload that reads as a clean, zero-resource cluster.
type State string

const (
	// StateOK means the scanner completed and its data is complete. It is the
	// zero value's meaning, so scanners that cannot fail need not set it.
	StateOK State = ""
	// StateDegraded means the scanner completed but some data is missing
	// because one or more API calls failed. The data present is real but
	// partial, so consumers must not read absent fields as zero.
	StateDegraded State = "degraded"
	// StateErrored means the scanner could not collect its data because an API
	// call failed or access was denied. The data must never be read as a real
	// "clean, zero resources" result.
	StateErrored State = "errored"
	// StateUnavailable means the scanned feature is genuinely absent, such as a
	// CRD that is not installed. This is a trustworthy "nothing here", not a
	// failure.
	StateUnavailable State = "unavailable"
)

// Result holds the output of a single scanner run against one cluster.
type Result struct {
	// Scanner is the name identifying which scanner produced this result.
	Scanner string `json:"scanner"`
	// State records how much to trust Data. The zero value means StateOK.
	State State `json:"state,omitempty"`
	// Reason is a short explanation when State is not OK. Empty otherwise.
	Reason string `json:"reason,omitempty"`
	// Data is the scanner-specific payload.
	Data any `json:"data"`
}

// Blind reports whether the scanner failed to observe the cluster, so its data
// is a failed read rather than a measurement and must be excluded from fleet
// statistics instead of counted as zero.
func (r Result) Blind() bool {
	return r.State == StateErrored
}

// ErroredResult builds a result that records a failed scan for one cluster so
// the fleet report can surface the failure instead of dropping it silently.
func ErroredResult(name string, err error) Result {
	reason := "scan failed"
	if err != nil {
		reason = err.Error()
	}
	return Result{Scanner: name, State: StateErrored, Reason: reason}
}
