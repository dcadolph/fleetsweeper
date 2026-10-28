package server

import (
	"bytes"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// docsPathPattern matches one backtick-quoted path in an api.md table cell.
var docsPathPattern = regexp.MustCompile("`([^`]+)`")

// parseAPIDocRoutes reads the Endpoints table of api.md and returns the sorted
// "METHOD /path" pairs for /api routes and for root routes.
func parseAPIDocRoutes(t *testing.T, doc string) (api, root []string) {
	t.Helper()
	inTable := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| Method | Path |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 || strings.HasPrefix(strings.TrimSpace(cells[1]), "---") {
			continue
		}
		methods := strings.Split(strings.TrimSpace(cells[1]), ",")
		pathCell := strings.TrimSpace(cells[2])
		isRoot := strings.HasPrefix(pathCell, "root ")
		for _, m := range docsPathPattern.FindAllStringSubmatch(pathCell, -1) {
			for _, method := range methods {
				pair := strings.TrimSpace(method) + " " + m[1]
				if isRoot {
					root = append(root, pair)
				} else {
					api = append(api, pair)
				}
			}
		}
	}
	sort.Strings(api)
	sort.Strings(root)
	return api, root
}

// TestDocsAPIRoutes verifies the api.md Endpoints table lists every route the
// server registers and nothing the server does not register.
func TestDocsAPIRoutes(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	apiRoutes, rootRoutes := srv.apiRoutes(), srv.rootRoutes()
	wantAPI := make([]string, 0, len(apiRoutes))
	for _, r := range apiRoutes {
		wantAPI = append(wantAPI, r.Method+" "+r.Path)
	}
	wantRoot := make([]string, 0, len(rootRoutes))
	for _, r := range rootRoutes {
		wantRoot = append(wantRoot, r.Method+" "+r.Path)
	}
	sort.Strings(wantAPI)
	sort.Strings(wantRoot)

	raw, err := os.ReadFile("../../docs/reference/api.md")
	if err != nil {
		t.Fatalf("read api.md: %v", err)
	}
	gotAPI, gotRoot := parseAPIDocRoutes(t, string(raw))

	if diff := cmp.Diff(wantAPI, gotAPI); diff != "" {
		t.Errorf("api.md /api routes mismatch (-server +docs):\n%s", diff)
	}
	if diff := cmp.Diff(wantRoot, gotRoot); diff != "" {
		t.Errorf("api.md root routes mismatch (-server +docs):\n%s", diff)
	}
}

// docsMetricPattern matches one backticked fleetsweeper metric name in a doc table cell.
var docsMetricPattern = regexp.MustCompile("`(fleetsweeper_[a-z0-9_]+)`")

// typeLinePattern matches a Prometheus TYPE comment for a fleetsweeper family.
var typeLinePattern = regexp.MustCompile(`(?m)^# TYPE (fleetsweeper_[a-z0-9_]+) `)

// TestDocsPrometheusMetrics verifies the prometheus.md metric table lists every family the
// server emits and nothing the server does not emit.
func TestDocsPrometheusMetrics(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)

	var buf bytes.Buffer
	srv.writeMetrics(t.Context(), &buf)
	got := map[string]bool{}
	for _, m := range typeLinePattern.FindAllStringSubmatch(buf.String(), -1) {
		got[m[1]] = true
	}

	// Families the demo seed does not trigger, each emitted only under the named condition.
	for _, name := range []string{
		// Emitted only when the server has admission metrics configured.
		"fleetsweeper_admission_decisions_total",
		"fleetsweeper_admission_check_failures_total",
		// Emitted only once a scan has run since startup.
		"fleetsweeper_last_scan_duration_seconds",
		// Emitted only when the policy-reports scanner returned data.
		"fleetsweeper_policy_results_total",
	} {
		got[name] = true
	}

	raw, err := os.ReadFile("../../docs/integrations/prometheus.md")
	if err != nil {
		t.Fatalf("read prometheus.md: %v", err)
	}
	doc := string(raw)
	start := strings.Index(doc, "| Metric |")
	end := strings.Index(doc, "## Starter dashboards")
	if start < 0 || end < start {
		t.Fatal("prometheus.md metric table not found")
	}
	want := map[string]bool{}
	for _, line := range strings.Split(doc[start:end], "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			continue
		}
		for _, m := range docsMetricPattern.FindAllStringSubmatch(cells[1], -1) {
			want[m[1]] = true
		}
	}

	for name := range got {
		if !want[name] {
			t.Errorf("%s is emitted by the server but missing from prometheus.md", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s is listed in prometheus.md but missing from the server", name)
		}
	}
}
