package cmd

import (
	"errors"
	"fmt"
	"testing"
)

// TestExitCode verifies the error-to-exit-code mapping, including wrapped
// sentinels and the general-error fallthrough.
func TestExitCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In       error
		WantCode int
	}{
		{In: ErrNoContexts, WantCode: CodeNoContexts},                   // Test 0: No contexts sentinel.
		{In: ErrNoClients, WantCode: CodeConnectionError},               // Test 1: Connection sentinel.
		{In: ErrNoDatabase, WantCode: CodeNoDB},                         // Test 2: Missing database sentinel.
		{In: fmt.Errorf("wrap: %w", ErrNoDatabase), WantCode: CodeNoDB}, // Test 3: Wrapped sentinel still maps.
		{In: errors.New("boom"), WantCode: CodeGeneralError},            // Test 4: Unknown error is general.
		{In: nil, WantCode: CodeGeneralError},                           // Test 5: Nil defaults to general.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := exitCode(test.In); got != test.WantCode {
				t.Errorf("test %d: got %d, want %d", testNum, got, test.WantCode)
			}
		})
	}
}
