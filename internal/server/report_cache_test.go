package server

import (
	"fmt"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestReportCache verifies a repeat request for one scan and options reuses the report, while
// new options or a new scan build another, and the cache stays within its size.
func TestReportCache(t *testing.T) {
	t.Parallel()
	clusters := []string{"a", "b", "c"}
	results := map[string]map[string]scanner.Result{}
	for i, c := range clusters {
		results[c] = map[string]scanner.Result{"security": {Scanner: "security", Data: map[string]any{"enforced_count": float64(i)}}}
	}
	tagged := report.BuildOptions{ClusterTags: map[string]string{"a": "x", "b": "x", "c": "y"}}
	retagged := report.BuildOptions{ClusterTags: map[string]string{"a": "x", "b": "y", "c": "y"}}
	var c reportCache
	first := c.get("s1", clusters, results, tagged)
	tests := []struct {
		Opts     report.BuildOptions
		ScanID   string
		WantSame bool
	}{{ // Test 0: Same scan, same options.
		ScanID: "s1", Opts: tagged, WantSame: true,
	}, { // Test 1: Same scan, new tags.
		ScanID: "s1", Opts: retagged,
	}, { // Test 2: New scan, same options.
		ScanID: "s2", Opts: tagged,
	}}
	for testNum, test := range tests {
		if got := c.get(test.ScanID, clusters, results, test.Opts) == first; got != test.WantSame {
			t.Errorf("test %d: same report %v, want %v", testNum, got, test.WantSame)
		}
	}
	for i := range reportCacheSize + 5 {
		c.get(fmt.Sprintf("fill-%d", i), clusters, results, tagged)
	}
	if len(c.entries) != reportCacheSize || len(c.order) != reportCacheSize {
		t.Errorf("cache holds %d entries and %d keys, want %d", len(c.entries), len(c.order), reportCacheSize)
	}
}
