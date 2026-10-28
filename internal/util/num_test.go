package util

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestFloat64 verifies the numeric kinds Float64 accepts and the ones it rejects.
func TestFloat64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         any
		WantResult float64
		WantOK     bool
	}{
		{In: 1.5, WantResult: 1.5, WantOK: true},          // Test 0: float64.
		{In: float32(2.5), WantResult: 2.5, WantOK: true}, // Test 1: float32.
		{In: 3, WantResult: 3, WantOK: true},              // Test 2: int.
		{In: int32(4), WantResult: 4, WantOK: true},       // Test 3: int32.
		{In: int64(-5), WantResult: -5, WantOK: true},     // Test 4: int64.
		{In: "6", WantResult: 0, WantOK: false},           // Test 5: Numeric string.
		{In: nil, WantResult: 0, WantOK: false},           // Test 6: Nil.
		{In: true, WantResult: 0, WantOK: false},          // Test 7: Bool.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, ok := Float64(test.In)
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantOK, ok); diff != "" {
				t.Errorf("ok mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMedian verifies odd, even, unsorted, and empty inputs, and that the input is left as is.
func TestMedian(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         []float64
		WantResult float64
	}{
		{In: []float64{3, 1, 2}, WantResult: 2},          // Test 0: Odd count, unsorted.
		{In: []float64{4, 1, 3, 2}, WantResult: 2.5},     // Test 1: Even count averages the pair.
		{In: []float64{7}, WantResult: 7},                // Test 2: Single value.
		{In: nil, WantResult: 0},                         // Test 3: Empty input.
		{In: []float64{-1, -1, 10, 10}, WantResult: 4.5}, // Test 4: Even count across zero.
		{In: []float64{0, 0, 0, 0, 0, 9}, WantResult: 0}, // Test 5: Mostly zero.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			in := append([]float64(nil), test.In...)
			if diff := cmp.Diff(test.WantResult, Median(in)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.In, in); diff != "" {
				t.Errorf("input reordered (-want +got):\n%s", diff)
			}
		})
	}
}
