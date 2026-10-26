package scanner

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestNames verifies scanner names are collected once each across clusters, sorted.
func TestNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         map[string]map[string]Result
		WantResult []string
	}{{ // Test 0: Nil results yield no names.
		In: nil, WantResult: nil,
	}, { // Test 1: Names shared and unique across clusters are deduplicated and sorted.
		In: map[string]map[string]Result{
			"a": {"version": {}, "crds": {}},
			"b": {"version": {}, "rbac": {}},
		},
		WantResult: []string{"crds", "rbac", "version"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, Names(test.In), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
