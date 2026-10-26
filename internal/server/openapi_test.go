package server

import (
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestOpenAPISpec_ValidYAML verifies the embedded openapi.yaml parses
// and that the expected new paths (alerts, timeline, webhooks) are
// present so a Swagger UI or codegen run doesn't fail downstream.
func TestOpenAPISpec_ValidYAML(t *testing.T) {
	t.Parallel()
	var doc map[string]any
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("openapi.yaml parse error: %v", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("openapi.yaml missing top-level paths map")
	}
	wantPaths := []string{
		"/api/alerts",
		"/api/alerts/{fingerprint}/ack",
		"/api/webhooks/alertmanager",
		"/api/webhooks/falco",
		"/api/clusters/{name}/timeline",
	}
	for _, p := range wantPaths {
		if _, ok := paths[p]; !ok {
			t.Errorf("missing path %q in openapi.yaml; available: %s",
				p, strings.Join(mapKeys(paths), ", "))
		}
	}
}

// mapKeys returns the keys of a map[string]any in deterministic-ish
// order, just for the diagnostic message above.
func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestOpenAPIMatchesRoutes verifies openapi.yaml documents every method and
// path the server serves, under /api and at the root, and nothing it does not
// serve.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	served := map[string]bool{}
	for _, r := range srv.apiRoutes() {
		served[strings.ToLower(r.Method)+" /api"+r.Path] = true
	}
	for _, r := range srv.rootRoutes() {
		served[strings.ToLower(r.Method)+" "+r.Path] = true
	}

	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("openapi.yaml parse error: %v", err)
	}
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		for method := range ops {
			switch method {
			case "get", "put", "post", "delete", "patch":
				documented[method+" "+path] = true
			}
		}
	}

	var missing, extra []string
	for k := range served {
		if !documented[k] {
			missing = append(missing, k)
		}
	}
	for k := range documented {
		if !served[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("served but not in openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("in openapi.yaml but not served:\n  %s", strings.Join(extra, "\n  "))
	}
}
