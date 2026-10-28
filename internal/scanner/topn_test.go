package scanner

import (
	"cmp"
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestTopN verifies TopN sorts by the comparator, truncates to n, keeps tied items in input
// order, and handles n beyond the length and an empty input.
func TestTopN(t *testing.T) {
	t.Parallel()
	type item struct {
		Key  int
		Name string
	}
	byKeyDesc := func(a, b item) int { return cmp.Compare(b.Key, a.Key) }
	tests := []struct {
		In         []item
		WantResult []item
		N          int
	}{{ // Test 0: Sorted descending and cut to n.
		In:         []item{{1, "a"}, {3, "b"}, {2, "c"}},
		N:          2,
		WantResult: []item{{3, "b"}, {2, "c"}},
	}, { // Test 1: Ties keep input order.
		In:         []item{{1, "x"}, {2, "y"}, {1, "w"}, {2, "z"}},
		N:          3,
		WantResult: []item{{2, "y"}, {2, "z"}, {1, "x"}},
	}, { // Test 2: n beyond the length returns every item.
		In:         []item{{1, "a"}, {2, "b"}},
		N:          10,
		WantResult: []item{{2, "b"}, {1, "a"}},
	}, { // Test 3: Empty input.
		N: 5,
	}, { // Test 4: Zero n returns nothing.
		In: []item{{1, "a"}},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := TopN(test.In, test.N, byKeyDesc)
			if diff := gocmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
