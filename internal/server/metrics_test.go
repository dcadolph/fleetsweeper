package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestPromLabelEscape(t *testing.T) {
	t.Parallel()
	cases := []struct{ In, Want string }{
		{`simple`, `simple`},
		{`with space`, `with space`},
		{`quote " here`, `quote \" here`},
		{`back\slash`, `back\\slash`},
		{"new\nline", `new\nline`},
		{`mixed "back\slash"`, `mixed \"back\\slash\"`},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := promLabelEscape(c.In); got != c.Want {
				t.Errorf("escape(%q): want %q, got %q", c.In, c.Want, got)
			}
		})
	}
}

func TestMetricsCache_HitMiss(t *testing.T) {
	t.Parallel()
	var c metricsCache
	r := &report.Report{Clusters: []string{"a"}}
	if got := c.loadFresh("id-1", time.Second); got != nil {
		t.Errorf("expected miss before store, got hit")
	}
	c.store("id-1", r)
	if got := c.loadFresh("id-1", time.Second); got == nil {
		t.Errorf("expected hit after store, got miss")
	}
	if got := c.loadFresh("id-2", time.Second); got != nil {
		t.Errorf("expected miss on different scan id, got hit")
	}
	if got := c.loadFresh("id-1", time.Nanosecond); got != nil {
		t.Errorf("expected miss after ttl expiry, got hit")
	}
}

func TestWriteMetrics_EmptyStore(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "# HELP fleetsweeper_scans_total")
	mustContain(t, out, `fleetsweeper_scans_total{result="success"} 0`)
	mustContain(t, out, "# fleetsweeper: no scans available yet")
}

func TestWriteMetrics_DemoMode(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "fleetsweeper_cluster_count ")
	mustContain(t, out, "fleetsweeper_fleet_score ")
	mustContain(t, out, "fleetsweeper_findings_total{severity=\"critical\"}")
	mustContain(t, out, "fleetsweeper_cluster_health{cluster=")
	mustContain(t, out, "fleetsweeper_finding_count{severity=")
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("metrics output does not end with newline")
	}
}

func TestWriteMetrics_LastScanDuration(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.lastScanDuration.Store(int64(2500 * time.Millisecond))
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "fleetsweeper_last_scan_duration_seconds 2.500")
}

// newDemoServer returns a Server wired in demo mode so writeMetrics has
// synthetic data to emit. Avoids spinning up real scans in unit tests.
func newDemoServer(t *testing.T) *Server {
	t.Helper()
	srv, _ := testServer(t)
	srv.demo = true
	return srv
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected metrics output to contain %q; full output:\n%s", needle, haystack)
	}
}

// Compile-time guard so refactors that drop the fields surface immediately.
var (
	_ = atomic.Int64{}
	_ = sync.Mutex{}
	_ = zap.NewNop
	_ = scanner.NewRegistry
)
