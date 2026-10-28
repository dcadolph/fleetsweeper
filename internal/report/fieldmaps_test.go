package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestFieldMaps verifies scanner results convert to field maps with failures reported.
func TestFieldMaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In          map[string]scanner.Result
		WantResult  map[string]map[string]any
		WantErrText string
	}{{ // Test 0: Good result converts.
		In: map[string]scanner.Result{
			"nodes": {Data: map[string]any{"count": 3}},
		},
		WantResult: map[string]map[string]any{"nodes": {"count": float64(3)}},
	}, { // Test 1: Unmarshalable data is omitted and named in the error.
		In: map[string]scanner.Result{
			"good": {Data: map[string]any{"a": "b"}},
			"bad":  {Data: make(chan int)},
		},
		WantResult:  map[string]map[string]any{"good": {"a": "b"}},
		WantErrText: "scanner bad",
	}, { // Test 2: Empty input yields empty output.
		In:         map[string]scanner.Result{},
		WantResult: map[string]map[string]any{},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := FieldMaps(test.In)
			if (err != nil) != (test.WantErrText != "") ||
				(err != nil && !strings.Contains(err.Error(), test.WantErrText)) {
				t.Fatalf("error = %v, want text %q", err, test.WantErrText)
			}
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
