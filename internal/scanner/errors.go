package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
)

// ErrScan indicates a scanner failed to collect data from a cluster.
var ErrScan = errors.New("scan failed")

// ClassifyError maps an error from a scanner's list read to the State that read leaves the
// result in and a short reason. A resource type the server does not serve (NotFound on a
// list, or no REST mapping) is StateUnavailable: the feature is absent and nothing exists to
// measure. Every other failure, Forbidden and Unauthorized included, is StateErrored, because
// a read that was denied or failed observed nothing and must never count as a clean, empty
// cluster. A nil error is StateOK with no reason. ClassifyError is for list reads; a NotFound
// on a Get means the object is absent, not the type.
func ClassifyError(err error) (State, string) {
	if err == nil {
		return StateOK, ""
	}
	label := "api error"
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return StateUnavailable, "not served: " + err.Error()
	case apierrors.IsForbidden(err):
		label = "forbidden"
	case apierrors.IsUnauthorized(err):
		label = "unauthorized"
	case errors.Is(err, context.Canceled):
		label = "canceled"
	case errors.Is(err, context.DeadlineExceeded) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err):
		label = "timed out"
	case apierrors.IsTooManyRequests(err):
		label = "throttled"
	case apierrors.IsResourceExpired(err):
		label = "list expired"
	case apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsUnexpectedServerError(err):
		label = "server error"
	}
	return StateErrored, label + ": " + err.Error()
}

// Coverage folds the outcome of each API read a scanner makes into the State and Reason of its
// result. The zero value is ready to use.
type Coverage struct {
	// ok counts reads that succeeded.
	ok int
	// failures lists reads that failed, in the order observed.
	failures []readFailure
}

// readFailure is one failed read and its classification.
type readFailure struct {
	// state is the read's classified State.
	state State
	// reason names the read and explains the failure.
	reason string
	// err is the read's error.
	err error
}

// Observe records the outcome of one read, named by what (for example "secrets"), and reports
// whether it succeeded.
func (c *Coverage) Observe(what string, err error) bool {
	if err == nil {
		c.ok++
		return true
	}
	state, reason := ClassifyError(err)
	c.failures = append(c.failures, readFailure{state: state, reason: what + ": " + reason, err: err})
	return false
}

// Finish builds the scanner's result from data and the observed reads:
//
// Every read succeeded, or the only failures are types the server does not serve while some
// read succeeded: StateOK, since an absent type is nothing missing. Every read failed and every
// failure is an unserved type: StateUnavailable with data. Some read succeeded and another
// failed for any other reason: StateDegraded with data, which is real but partial. No read
// succeeded: StateErrored with no data, plus an error wrapping ErrScan and every read's error
// so the failure is logged and the data never counts as a measurement.
func (c *Coverage) Finish(name string, data any) (Result, error) {
	var reasons []string
	var errs []error
	allUnavailable := true
	for _, f := range c.failures {
		reasons = append(reasons, f.reason)
		errs = append(errs, f.err)
		if f.state != StateUnavailable {
			allUnavailable = false
		}
	}
	reason := strings.Join(reasons, "; ")
	switch {
	case len(c.failures) == 0 || (allUnavailable && c.ok > 0):
		return Result{Scanner: name, Data: data}, nil
	case allUnavailable:
		return Result{Scanner: name, State: StateUnavailable, Reason: reason, Data: data}, nil
	case c.ok > 0:
		return Result{Scanner: name, State: StateDegraded, Reason: reason, Data: data}, nil
	}
	return Result{Scanner: name, State: StateErrored, Reason: reason},
		&coverageError{msg: fmt.Sprintf("%s: %s: %s", ErrScan, name, reason), errs: append([]error{ErrScan}, errs...)}
}

// coverageError is the error Finish returns when no read succeeded. It wraps ErrScan and every
// failed read's error so callers can match either.
type coverageError struct {
	// msg is the full message.
	msg string
	// errs are the wrapped errors, ErrScan first.
	errs []error
}

// Error returns the message naming the scanner and each failed read.
func (e *coverageError) Error() string { return e.msg }

// Unwrap returns ErrScan and every failed read's error.
func (e *coverageError) Unwrap() []error { return e.errs }
