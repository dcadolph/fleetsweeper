package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"
)

// TestHandleOpenAPI_ServesSpec verifies the embedded OpenAPI document is
// served verbatim with a YAML content type.
func TestHandleOpenAPI_ServesSpec(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("content type want yaml, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "openapi") {
		t.Error("body does not look like an OpenAPI document")
	}
}

// TestOpenAPIDocument verifies the served spec carries the given build version.
func TestOpenAPIDocument(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantVersion string
		In          string
	}{{ // Test 0: Release version.
		In: "0.12.0", WantVersion: "0.12.0",
	}, { // Test 1: Development build.
		In: "dev", WantVersion: "dev",
	}, { // Test 2: Version with characters YAML would misread unquoted.
		In: "v1.0.0: rc #1", WantVersion: "v1.0.0: rc #1",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var doc struct {
				Info struct {
					Version string `yaml:"version"`
				} `yaml:"info"`
			}
			if err := yaml.Unmarshal(openAPIDocument(test.In), &doc); err != nil {
				t.Fatalf("parse served spec: %v", err)
			}
			if diff := cmp.Diff(test.WantVersion, doc.Info.Version); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
