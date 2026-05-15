package report

import (
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

func TestRenderHTML(t *testing.T) {
	t.Parallel()

	clusters := []string{"cluster-a", "cluster-b"}
	results := map[string]map[string]scanner.Result{
		"cluster-a": {
			"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.28.3"}},
		},
		"cluster-b": {
			"version": {Scanner: "version", Data: map[string]string{"git_version": "v1.29.0"}},
		},
	}

	rpt := Build(clusters, results)
	html, err := RenderHTML(rpt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content := string(html)
	// The HTML is now a JS-rendered dashboard. Check that the data payload
	// is embedded and the essential shell elements are present.
	checks := []string{
		"<!DOCTYPE html>",
		"Fleetsweeper",
		"cluster-a",
		"cluster-b",
		"v1.28.3",
		"v1.29.0",
		"var DATA =",
	}
	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("HTML output missing expected content: %q", check)
		}
	}
}
