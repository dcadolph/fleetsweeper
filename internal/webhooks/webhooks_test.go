package webhooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

func TestLoadConfig_EmptyPath(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\"): %v", err)
	}
	if cfg == nil || len(cfg.Webhooks) != 0 {
		t.Errorf("want empty config; got %+v", cfg)
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wh.yaml")
	if err := os.WriteFile(path, []byte(`webhooks:
  - name: test
    url: https://example.com/webhook
    min_severity: warning
    scanner_regex: "^node-"
    cluster_regex: "^prod-"
    headers:
      X-Token: $TEST_TOKEN
`), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Webhooks) != 1 {
		t.Fatalf("want 1 webhook; got %d", len(cfg.Webhooks))
	}
	if cfg.Webhooks[0].scannerRE == nil || cfg.Webhooks[0].clusterRE == nil {
		t.Errorf("regexes should have compiled; got %+v", cfg.Webhooks[0])
	}
}

func TestLoadConfig_InvalidRegex(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wh.yaml")
	_ = os.WriteFile(path, []byte(`webhooks:
  - name: bad
    url: https://x
    scanner_regex: "["
`), 0o644)
	if _, err := LoadConfig(path); err == nil {
		t.Errorf("expected error on bad regex")
	}
}

func TestLoadConfig_MissingURL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wh.yaml")
	_ = os.WriteFile(path, []byte(`webhooks:
  - name: noURL
`), 0o644)
	if _, err := LoadConfig(path); err == nil {
		t.Errorf("expected error for missing URL")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	t.Parallel()
	cases := []struct {
		Got, Want string
		OK        bool
	}{
		{"critical", "warning", true},
		{"warning", "warning", true},
		{"info", "warning", false},
		{"warning", "critical", false},
		{"unknown", "info", false},
	}
	for _, c := range cases {
		if got := severityAtLeast(c.Got, c.Want); got != c.OK {
			t.Errorf("severityAtLeast(%q,%q): want %v, got %v", c.Got, c.Want, c.OK, got)
		}
	}
}

func TestMatches_AllFilters(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wh.yaml")
	_ = os.WriteFile(path, []byte(`webhooks:
  - name: prod-criticals
    url: https://example
    min_severity: critical
    scanner_regex: "^node-"
    cluster_regex: "^prod-"
`), 0o644)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s := cfg.Webhooks[0]
	cases := []struct {
		Name string
		F    report.Finding
		OK   bool
	}{
		{"match", report.Finding{Severity: "critical", Cluster: "prod-east", Scanner: "node-health"}, true},
		{"wrong severity", report.Finding{Severity: "warning", Cluster: "prod-east", Scanner: "node-health"}, false},
		{"wrong cluster", report.Finding{Severity: "critical", Cluster: "dev-east", Scanner: "node-health"}, false},
		{"wrong scanner", report.Finding{Severity: "critical", Cluster: "prod-east", Scanner: "rbac"}, false},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := matches(s, c.F); got != c.OK {
				t.Errorf("want %v, got %v", c.OK, got)
			}
		})
	}
}

func TestDispatch_DeliversAndDedups(t *testing.T) {
	t.Parallel()
	var posts atomic.Int32
	var lastBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &Config{Webhooks: []Subscriber{{
		Name: "test", URL: ts.URL, MinSeverity: "warning",
	}}}
	if err := compile(cfg); err != nil {
		t.Fatalf("compile: %v", err)
	}
	d := NewDispatcher(cfg, NoopLogger{})
	d.SetClient(ts.Client())

	findings := []report.Finding{
		{Severity: "critical", Cluster: "c1", Scanner: "node-health", Title: "x"},
		{Severity: "info", Cluster: "c1", Scanner: "rbac", Title: "ignored"},
	}
	d.Dispatch(context.Background(), findings)
	if posts.Load() != 1 {
		t.Errorf("expected 1 delivery; got %d", posts.Load())
	}
	var got map[string]any
	if err := json.Unmarshal(lastBody, &got); err != nil {
		t.Errorf("default body should be JSON; got error %v\nbody=%s", err, lastBody)
	}
	if got["title"] != "x" {
		t.Errorf("body missing title; got %+v", got)
	}

	// Re-dispatch the same finding: dedup should suppress it.
	d.Dispatch(context.Background(), findings)
	if posts.Load() != 1 {
		t.Errorf("dedup failed; expected 1 total, got %d", posts.Load())
	}
}

func TestDispatch_RendersCustomTemplate(t *testing.T) {
	t.Parallel()
	body := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &Config{Webhooks: []Subscriber{{
		Name: "tmpl", URL: ts.URL, MinSeverity: "info",
		BodyTemplate: `{"alert":"{{.Title}}@{{.Cluster}}","sev":"{{.Severity}}"}`,
	}}}
	if err := compile(cfg); err != nil {
		t.Fatalf("compile: %v", err)
	}
	d := NewDispatcher(cfg, NoopLogger{})
	d.SetClient(ts.Client())
	d.Dispatch(context.Background(), []report.Finding{{
		Severity: "warning", Cluster: "prod-east", Scanner: "node-health", Title: "oom",
	}})
	select {
	case b := <-body:
		if !strings.Contains(string(b), `"alert":"oom@prod-east"`) {
			t.Errorf("template not rendered; got %s", b)
		}
	default:
		t.Errorf("no body received")
	}
}

func TestDispatch_HeadersAndEnvSubstitution(t *testing.T) {
	t.Setenv("WEBHOOK_TOKEN", "topsecret")
	got := make(chan http.Header, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	cfg := &Config{Webhooks: []Subscriber{{
		Name: "hdrs", URL: ts.URL, MinSeverity: "info",
		Headers: map[string]string{"X-Auth": "Bearer $WEBHOOK_TOKEN"},
	}}}
	_ = compile(cfg)
	d := NewDispatcher(cfg, NoopLogger{})
	d.SetClient(ts.Client())
	d.Dispatch(context.Background(), []report.Finding{{
		Severity: "info", Cluster: "c", Scanner: "s", Title: "t",
	}})
	hdrs := <-got
	if hdrs.Get("X-Auth") != "Bearer topsecret" {
		t.Errorf("env expansion failed in headers; got %q", hdrs.Get("X-Auth"))
	}
}

func TestDispatch_NilConfigIsNoOp(t *testing.T) {
	t.Parallel()
	d := NewDispatcher(nil, NoopLogger{})
	d.Dispatch(context.Background(), []report.Finding{{Severity: "critical"}})
}
