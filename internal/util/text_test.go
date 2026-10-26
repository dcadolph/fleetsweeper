package util

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestTruncate verifies rune-aware truncation with an ellipsis.
func TestTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
		N          int
	}{
		{In: "hello", N: 10, WantResult: "hello"},         // Test 0: Shorter than limit.
		{In: "hello", N: 5, WantResult: "hello"},          // Test 1: Exactly at limit.
		{In: "hello world", N: 5, WantResult: "hello..."}, // Test 2: Cut with ellipsis.
		{In: "héllo wörld", N: 5, WantResult: "héllo..."}, // Test 3: Multibyte runes.
		{In: "hello", N: 0, WantResult: "hello"},          // Test 4: Non-positive limit.
		{In: "", N: 3, WantResult: ""},                    // Test 5: Empty input.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, Truncate(test.In, test.N)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPlural verifies the plural suffix.
func TestPlural(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantResult string
		In         int
	}{
		{In: 0, WantResult: "s"}, // Test 0: Zero.
		{In: 1, WantResult: ""},  // Test 1: One.
		{In: 2, WantResult: "s"}, // Test 2: Many.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, Plural(test.In)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSanitizeName verifies DNS-1123 sanitization and the 253 character cap.
func TestSanitizeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
	}{
		{In: "Prod_US-east-1!", WantResult: "prod-us-east-1"},                // Test 0: Mixed characters.
		{In: "", WantResult: "unnamed"},                                      // Test 1: Empty.
		{In: "!!!", WantResult: "unnamed"},                                   // Test 2: Only invalid.
		{In: "a--b", WantResult: "a-b"},                                      // Test 3: Collapsed dashes.
		{In: strings.Repeat("a", 300), WantResult: strings.Repeat("a", 253)}, // Test 4: Capped.
		// Test 5: A cut that lands on a dash is trimmed so the name still ends alphanumeric.
		{In: strings.Repeat("a", 252) + "-bcd", WantResult: strings.Repeat("a", 252)},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, SanitizeName(test.In)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSeverityRank verifies severity weights.
func TestSeverityRank(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult int
	}{
		{In: "critical", WantResult: 3}, // Test 0: Critical.
		{In: "warning", WantResult: 2},  // Test 1: Warning.
		{In: "info", WantResult: 1},     // Test 2: Info.
		{In: "bogus", WantResult: 0},    // Test 3: Unknown.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, SeverityRank(test.In)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSeverityAtLeast verifies threshold comparison.
func TestSeverityAtLeast(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Got        string
		Want       string
		WantResult bool
	}{
		{Got: "critical", Want: "warning", WantResult: true}, // Test 0: Above.
		{Got: "warning", Want: "warning", WantResult: true},  // Test 1: Equal.
		{Got: "info", Want: "warning", WantResult: false},    // Test 2: Below.
		{Got: "info", Want: "", WantResult: true},            // Test 3: Empty threshold.
		{Got: "", Want: "info", WantResult: false},           // Test 4: Empty value.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, SeverityAtLeast(test.Got, test.Want)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
