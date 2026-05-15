package jsonutil

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMarshal(t *testing.T) {
	t.Parallel()

	type input struct {
		// Name is used for test readability.
		Name string `json:"name"`
	}

	tests := []struct {
		WantResult string
		Want       error
		In         any
		Pretty     bool
	}{{ // Test 0: Compact output.
		In:         input{Name: "test"},
		Pretty:     false,
		WantResult: `{"name":"test"}`,
		Want:       nil,
	}, { // Test 1: Pretty output.
		In:     input{Name: "test"},
		Pretty: true,
		WantResult: `{
  "name": "test"
}`,
		Want: nil,
	}, { // Test 2: Nil input.
		In:         nil,
		Pretty:     false,
		WantResult: "null",
		Want:       nil,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Marshal(test.In, test.Pretty)
			if test.Want != nil && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if test.Want == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
