package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// staticFiles returns every embedded static file under dir with the given
// extension, as paths relative to static/.
func staticFiles(t *testing.T, ext string) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ext) && !strings.HasPrefix(p, "static/vendor/") {
			out = append(out, strings.TrimPrefix(p, "static/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk static: %v", err)
	}
	sort.Strings(out)
	return out
}

// TestStaticAssetsServed verifies the dashboard shell, every module, and every
// stylesheet are served with the right content type.
func TestStaticAssetsServed(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	h := srv.Handler()
	js := staticFiles(t, ".js")
	css := staticFiles(t, ".css")
	if len(js) < 20 || len(css) < 3 {
		t.Fatalf("found %d modules and %d stylesheets, the embed is missing files", len(js), len(css))
	}
	for _, p := range append(append([]string{""}, js...), css...) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+p, nil))
		if w.Code != http.StatusOK {
			t.Errorf("/%s: status %d", p, w.Code)
			continue
		}
		ct := w.Header().Get("Content-Type")
		switch {
		case strings.HasSuffix(p, ".js") && !strings.Contains(ct, "javascript"):
			t.Errorf("/%s: content type %q", p, ct)
		case strings.HasSuffix(p, ".css") && !strings.HasPrefix(ct, "text/css"):
			t.Errorf("/%s: content type %q", p, ct)
		}
	}
}

// importRe matches the module path of a static import.
var importRe = regexp.MustCompile(`(?m)^import (?:[^'"]+ from )?'([^']+)';`) //nolint:gochecknoglobals // Not modified, simplifies testing.

// TestStaticImportsResolve verifies every relative import in every module
// names an embedded file, so a renamed module cannot leave the page blank.
func TestStaticImportsResolve(t *testing.T) {
	t.Parallel()
	for _, p := range staticFiles(t, ".js") {
		if !strings.HasPrefix(p, "js/") {
			continue
		}
		src, err := fs.ReadFile(staticFS, "static/"+p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		for _, m := range importRe.FindAllStringSubmatch(string(src), -1) {
			target := path.Join(path.Dir(p), m[1])
			if _, err := fs.Stat(staticFS, "static/"+target); err != nil {
				t.Errorf("%s imports %s, which is not embedded", p, m[1])
			}
		}
	}
}

// TestRouteTable verifies the route table lists the 18 dashboard views.
func TestRouteTable(t *testing.T) {
	t.Parallel()
	src, err := fs.ReadFile(staticFS, "static/js/routes.js")
	if err != nil {
		t.Fatalf("read routes: %v", err)
	}
	matches := regexp.MustCompile(`\{ id: '([a-zA-Z]+)'`).FindAllStringSubmatch(string(src), -1)
	got := make([]string, 0, len(matches))
	for _, m := range matches {
		got = append(got, m[1])
	}
	sort.Strings(got)
	want := []string{
		"alerts", "capacity", "clusters", "cohorts", "dash", "detail", "drift", "findings", "globe",
		"groups", "heatmap", "incidents", "manage", "outliers", "replay", "scanReport", "scans", "trends",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("route ids mismatch (-want +got):\n%s", diff)
	}
}

// TestNoInlineHandlers verifies no module or page carries an inline event
// handler or inline script, which the Content-Security-Policy would block.
func TestNoInlineHandlers(t *testing.T) {
	t.Parallel()
	handler := regexp.MustCompile(`\son[a-z]+=`)
	files := append(staticFiles(t, ".js"), staticFiles(t, ".html")...)
	styles := 0
	for _, p := range files {
		src, err := fs.ReadFile(staticFS, "static/"+p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if loc := handler.FindIndex(src); loc != nil {
			t.Errorf("%s has an inline handler near %q", p, src[loc[0]:min(loc[1]+20, len(src))])
		}
		if strings.HasSuffix(p, ".html") && regexp.MustCompile(`<script>|<script [^>]*>[^<]`).Match(src) {
			t.Errorf("%s has an inline script", p)
		}
		if strings.HasPrefix(p, "js/") {
			styles += strings.Count(string(src), `style="`)
		}
	}
	if styles >= 20 {
		t.Errorf("modules carry %d style attributes, want fewer than 20", styles)
	}
}
