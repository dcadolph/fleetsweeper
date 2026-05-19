package server

import (
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
