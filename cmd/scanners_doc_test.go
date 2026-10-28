package cmd

import (
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// scannerKeyRow matches a scanner table row and captures the backticked Key column.
var scannerKeyRow = regexp.MustCompile("(?m)^\\|[^|]+\\| +`([a-z-]+)` +\\|[^|]+\\|$")

// docScannerKeys returns the sorted Key column values found in the scanners doc text.
func docScannerKeys(doc string) []string {
	matches := scannerKeyRow.FindAllStringSubmatch(doc, -1)
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, m[1])
	}
	sort.Strings(keys)
	return keys
}

// TestScannersDocKeys checks that the scanners doc Key column matches the registry.
func TestScannersDocKeys(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../docs/concepts/scanners.md")
	if err != nil {
		t.Fatalf("read doc: %v", err)
	}
	doc := string(raw)
	tests := []struct {
		In       string
		WantKeys []string
	}{{ // Test 0: Doc keys equal the registry names.
		In: doc, WantKeys: buildRegistry().Names(),
	}}
	for testNum, test := range tests {
		t.Run("test "+string(rune('0'+testNum)), func(t *testing.T) {
			t.Parallel()
			got := docScannerKeys(test.In)
			if diff := cmp.Diff(test.WantKeys, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("doc keys mismatch (-registry +doc):\n%s", diff)
			}
		})
	}
}
