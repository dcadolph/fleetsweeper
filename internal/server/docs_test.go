package server

import (
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
