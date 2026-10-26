package report

import (
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestRenderHTML verifies the report HTML embeds the data payload and the shell, and inlines
// Chart.js rather than loading it.
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
	// The report renders offline from file://, so Chart.js is inline and nothing loads remotely.
	if !strings.Contains(content, string(ChartJS[:200])) {
		t.Error("HTML output does not inline the vendored Chart.js")
	}
	if strings.Contains(content, "<script src=") {
		t.Error("HTML output loads a remote script")
	}
}
