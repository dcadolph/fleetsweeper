package report

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// sortedKeys returns the keys of m in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// TestScannerCatalogKeySets verifies that every scanner catalog names the same scanners and that
// each scanner sits in exactly one category.
func TestScannerCatalogKeySets(t *testing.T) {
	t.Parallel()
	inCategories := map[string]int{}
	for _, c := range Categories() {
		for _, s := range c.Scanners {
			inCategories[s]++
		}
	}
	tests := []struct {
		Name     string
		Keys     []string
		WantKeys []string
	}{
		{ // Test 0: Descriptions match labels.
			Name: "descriptions", Keys: sortedKeys(ScannerDescriptions),
			WantKeys: sortedKeys(ScannerLabels),
		},
		{ // Test 1: Inspect commands match labels.
			Name: "inspect", Keys: sortedKeys(scannerInspect),
			WantKeys: sortedKeys(ScannerLabels),
		},
		{ // Test 2: Category scanners match labels.
			Name: "categories", Keys: sortedKeys(inCategories),
			WantKeys: sortedKeys(ScannerLabels),
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantKeys, test.Keys, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("%s key set mismatch (-want +got):\n%s", test.Name, diff)
			}
		})
	}
	for scanner, n := range inCategories {
		if n != 1 {
			t.Errorf("scanner %q appears in %d categories, want 1", scanner, n)
		}
	}
}

// TestCategoryOf verifies the category lookup for known, unknown, and empty scanner names.
func TestCategoryOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner    string
		WantResult string
	}{
		{Scanner: "cluster-info", WantResult: "Health & Resources"}, // Test 0: Known scanner.
		{Scanner: "events", WantResult: "Events & Logs"},            // Test 1: Events.
		{Scanner: "nope", WantResult: "Other"},                      // Test 2: Unknown scanner.
		{Scanner: "", WantResult: "Other"},                          // Test 3: Empty scanner.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, CategoryOf(test.Scanner)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
