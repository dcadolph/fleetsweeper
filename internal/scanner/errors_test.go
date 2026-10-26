package scanner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestClassifyError verifies each API failure maps to the documented State and reason label.
func TestClassifyError(t *testing.T) {
	t.Parallel()
	gr := schema.GroupResource{Resource: "secrets"}
	denied := errors.New("denied")
	tests := []struct {
		In         error
		WantState  State
		WantPrefix string
	}{
		{In: nil, WantState: StateOK, WantPrefix: ""},                                                     // Test 0: Success.
		{In: apierrors.NewNotFound(gr, ""), WantState: StateUnavailable, WantPrefix: "not served: "},      // Test 1: Type not served.
		{In: &meta.NoResourceMatchError{}, WantState: StateUnavailable, WantPrefix: "not served: "},       // Test 2: No REST mapping.
		{In: apierrors.NewForbidden(gr, "", denied), WantState: StateErrored, WantPrefix: "forbidden: "},  // Test 3: RBAC denial is blind.
		{In: apierrors.NewUnauthorized("x"), WantState: StateErrored, WantPrefix: "unauthorized: "},       // Test 4: Bad credentials.
		{In: context.DeadlineExceeded, WantState: StateErrored, WantPrefix: "timed out: "},                // Test 5: Client deadline.
		{In: apierrors.NewTimeoutError("x", 1), WantState: StateErrored, WantPrefix: "timed out: "},       // Test 6: Server timeout status.
		{In: context.Canceled, WantState: StateErrored, WantPrefix: "canceled: "},                         // Test 7: Canceled scan.
		{In: apierrors.NewTooManyRequests("x", 1), WantState: StateErrored, WantPrefix: "throttled: "},    // Test 8: Throttled.
		{In: apierrors.NewInternalError(denied), WantState: StateErrored, WantPrefix: "server error: "},   // Test 9: 500.
		{In: apierrors.NewServiceUnavailable("x"), WantState: StateErrored, WantPrefix: "server error: "}, // Test 10: 503.
		{In: apierrors.NewResourceExpired("x"), WantState: StateErrored, WantPrefix: "list expired: "},    // Test 11: 410.
		{In: errors.New("boom"), WantState: StateErrored, WantPrefix: "api error: "},                      // Test 12: Unknown.
		{In: fmt.Errorf("page 2: %w", apierrors.NewForbidden(gr, "", denied)), WantState: StateErrored, // Test 13: Wrapped.
			WantPrefix: "forbidden: "},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			state, reason := ClassifyError(test.In)
			if state != test.WantState {
				t.Errorf("state = %q, want %q", state, test.WantState)
			}
			want := test.WantPrefix
			if test.In != nil {
				want += test.In.Error()
			}
			if diff := cmp.Diff(want, reason); diff != "" {
				t.Errorf("reason mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCoverageFinish verifies how read outcomes fold into one result.
func TestCoverageFinish(t *testing.T) {
	t.Parallel()
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("denied"))
	notServed := apierrors.NewNotFound(schema.GroupResource{Resource: "certificates"}, "")
	type read struct {
		What string
		Err  error
	}
	tests := []struct {
		Reads      []read
		WantState  State
		WantReason string
		WantData   bool
		WantErr    bool
	}{{ // Test 0: No reads is OK.
		WantState: StateOK, WantData: true,
	}, { // Test 1: Every read succeeded.
		Reads: []read{{"a", nil}, {"b", nil}}, WantState: StateOK, WantData: true,
	}, { // Test 2: An unserved type beside a good read is not degradation.
		Reads: []read{{"a", nil}, {"certificates", notServed}}, WantState: StateOK, WantData: true,
	}, { // Test 3: Every read unserved is unavailable, with data.
		Reads: []read{{"certificates", notServed}}, WantState: StateUnavailable, WantData: true,
		WantReason: "certificates: not served: " + notServed.Error(),
	}, { // Test 4: One denied read beside a good read is degraded, with data.
		Reads: []read{{"a", nil}, {"secrets", forbidden}}, WantState: StateDegraded, WantData: true,
		WantReason: "secrets: forbidden: " + forbidden.Error(),
	}, { // Test 5: Every read denied is errored, with no data and an error.
		Reads: []read{{"secrets", forbidden}, {"b", forbidden}}, WantState: StateErrored, WantErr: true,
		WantReason: "secrets: forbidden: " + forbidden.Error() + "; b: forbidden: " + forbidden.Error(),
	}, { // Test 6: Denied plus unserved with nothing read is errored.
		Reads: []read{{"secrets", forbidden}, {"certificates", notServed}}, WantState: StateErrored, WantErr: true,
		WantReason: "secrets: forbidden: " + forbidden.Error() + "; certificates: not served: " + notServed.Error(),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var cov Coverage
			for _, r := range test.Reads {
				if got := cov.Observe(r.What, r.Err); got != (r.Err == nil) {
					t.Errorf("Observe(%s) = %v, want %v", r.What, got, r.Err == nil)
				}
			}
			res, err := cov.Finish("x", "payload")
			if res.Scanner != "x" || res.State != test.WantState {
				t.Errorf("result %s/%q, want x/%q", res.Scanner, res.State, test.WantState)
			}
			if diff := cmp.Diff(test.WantReason, res.Reason); diff != "" {
				t.Errorf("reason mismatch (-want +got):\n%s", diff)
			}
			if (res.Data != nil) != test.WantData {
				t.Errorf("data present = %v, want %v", res.Data != nil, test.WantData)
			}
			if (err != nil) != test.WantErr {
				t.Fatalf("err = %v, want error %v", err, test.WantErr)
			}
			if err != nil && (!errors.Is(err, ErrScan) || !apierrors.IsForbidden(err)) {
				t.Errorf("error must wrap ErrScan and the read's error, got %v", err)
			}
		})
	}
}
