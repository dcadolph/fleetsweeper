package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// reportCacheSize is how many rebuilt reports the cache holds: two series windows of the
// widest history a request may ask for.
const reportCacheSize = 2 * maxHistoryScans

// reportCache holds reports rebuilt from stored scans, keyed by scan ID and the build options,
// so series endpoints do not rebuild every scan on every request. A stored scan never changes,
// and new cohort tags or groups change the key. Cached reports are shared and read-only: a
// caller that changes a report, such as marking acks on its findings, builds its own.
type reportCache struct {
	// mu guards entries and order.
	mu sync.Mutex
	// entries maps a key to its report.
	entries map[string]*report.Report
	// order lists keys oldest first, for eviction.
	order []string
}

// optionsKey returns a stable encoding of the parts of opts a stored scan's report depends on
// beyond the scan itself.
func optionsKey(opts report.BuildOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "t=%g;", opts.OutlierThreshold)
	tags := make([]string, 0, len(opts.ClusterTags))
	for c, t := range opts.ClusterTags {
		tags = append(tags, c+"="+t)
	}
	sort.Strings(tags)
	b.WriteString(strings.Join(tags, ","))
	groups := make([]string, 0, len(opts.Groups))
	for g, members := range opts.Groups {
		sorted := append([]string(nil), members...)
		sort.Strings(sorted)
		groups = append(groups, g+"="+strings.Join(sorted, "+"))
	}
	sort.Strings(groups)
	b.WriteString(";" + strings.Join(groups, ","))
	return b.String()
}

// get returns the cached report for the scan and options, building and storing it on a miss.
func (c *reportCache) get(scanID string, clusters []string, results map[string]map[string]scanner.Result,
	opts report.BuildOptions) *report.Report {
	key := scanID + "\x00" + optionsKey(opts)
	c.mu.Lock()
	if r, ok := c.entries[key]; ok {
		c.mu.Unlock()
		return r
	}
	c.mu.Unlock()
	r := report.Build(clusters, results, opts)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*report.Report, reportCacheSize)
	}
	if _, ok := c.entries[key]; !ok {
		c.entries[key] = r
		c.order = append(c.order, key)
		for len(c.order) > reportCacheSize {
			delete(c.entries, c.order[0])
			c.order = c.order[1:]
		}
	}
	return c.entries[key]
}
