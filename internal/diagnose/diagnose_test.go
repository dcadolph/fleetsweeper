package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRun_AllOff(t *testing.T) {
	// Clear all OTel env vars for this run.
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
	r := Run(context.Background(), Options{})
	if len(r.Results) == 0 {
		t.Fatalf("expected results, got none")
	}
	if r.HasFailures() {
		t.Errorf("no checks configured, none should have failed; got %+v", r)
	}
	for _, res := range r.Results {
		if res.Status != StatusOff {
			t.Errorf("expected %s=off when not configured; got %s", res.Name, res.Status)
		}
	}
}

func TestRun_FleetDriftAndPolicyReport_Writable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := Run(context.Background(), Options{
		FleetDriftOutputDir:   dir,
		PolicyReportOutputDir: dir,
	})
	for _, res := range r.Results {
		if res.Name == "FleetDriftReport output" || res.Name == "PolicyReport output" {
			if res.Status != StatusOK {
				t.Errorf("%s: want ok, got %s (%s)", res.Name, res.Status, res.Message)
			}
		}
	}
}

func TestRun_FleetDriftOutput_Unwritable(t *testing.T) {
	t.Parallel()
	// Pick a path that can't possibly exist under a read-only root.
	r := Run(context.Background(), Options{
		FleetDriftOutputDir: "/proc/0/forbidden/fleetdrift",
	})
	for _, res := range r.Results {
		if res.Name == "FleetDriftReport output" {
			if res.Status != StatusFail {
				t.Errorf("expected fail for unwritable path, got %s", res.Status)
			}
		}
	}
}

func TestRun_CostCSV_OK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cost.csv")
	if err := os.WriteFile(path, []byte("cluster,period,cost_usd\na,2026-05,1.00\n"), 0o644); err != nil {
		t.Fatalf("write tmp csv: %v", err)
	}
	r := Run(context.Background(), Options{CostCSVPath: path})
	for _, res := range r.Results {
		if res.Name == "Cost CSV" {
			if res.Status != StatusOK {
				t.Errorf("want ok, got %s (%s)", res.Status, res.Message)
			}
			if !strings.Contains(res.Message, "1 clusters") {
				t.Errorf("message lacks count: %s", res.Message)
			}
		}
	}
}

func TestRun_CostCSV_BadFile(t *testing.T) {
	t.Parallel()
	r := Run(context.Background(), Options{CostCSVPath: "/does/not/exist.csv"})
	for _, res := range r.Results {
		if res.Name == "Cost CSV" && res.Status != StatusFail {
			t.Errorf("want fail on missing file, got %s", res.Status)
		}
	}
}

func TestRun_Slack_URLValidation(t *testing.T) {
	t.Parallel()
	r := Run(context.Background(), Options{SlackWebhookURL: "https://hooks.slack.com/services/foo/bar"})
	for _, res := range r.Results {
		if res.Name == "Slack webhook" && res.Status != StatusOK {
			t.Errorf("want ok for valid URL, got %s (%s)", res.Status, res.Message)
		}
	}
}

func TestRun_Slack_BadURL(t *testing.T) {
	t.Parallel()
	r := Run(context.Background(), Options{SlackWebhookURL: "http://insecure.example/webhook"})
	for _, res := range r.Results {
		if res.Name == "Slack webhook" && res.Status != StatusFail {
			t.Errorf("want fail for http URL, got %s (%s)", res.Status, res.Message)
		}
	}
}

func TestRun_Slack_Probe(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	r := Run(context.Background(), Options{
		SlackWebhookURL: ts.URL,
		Probe:           true,
		HTTPClient:      ts.Client(),
	})
	for _, res := range r.Results {
		if res.Name == "Slack webhook" {
			// TLS test server URL passes our parse check (it has https scheme).
			if res.Status != StatusOK {
				t.Errorf("probe: want ok, got %s (%s)", res.Status, res.Message)
			}
		}
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 hit on the webhook, got %d", hits.Load())
	}
}

func TestRun_GitHub_Probe_Authorized(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer real-token-1234567890" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat"})
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	// Override the GitHub host by injecting our own client and faking the URL.
	// We can't easily replace api.github.com, so this test just validates the
	// shorter-than-10 reject path; full integration is covered by the
	// remediate package tests.
	r := Run(context.Background(), Options{
		GitHubToken: "short",
		Probe:       true,
		HTTPClient:  ts.Client(),
	})
	for _, res := range r.Results {
		if res.Name == "GitHub token" && res.Status != StatusFail {
			t.Errorf("want fail for short token, got %s", res.Status)
		}
	}
}

func TestSummaryAndHasFailures(t *testing.T) {
	t.Parallel()
	r := Report{Results: []Result{
		{Status: StatusOK}, {Status: StatusOK}, {Status: StatusOff},
		{Status: StatusFail}, {Status: StatusWarn},
	}}
	s := r.Summary()
	if s[StatusOK] != 2 || s[StatusOff] != 1 || s[StatusWarn] != 1 || s[StatusFail] != 1 {
		t.Errorf("summary: %+v", s)
	}
	if !r.HasFailures() {
		t.Errorf("expected HasFailures=true")
	}
}

func TestFormatText_PlainAndTTY(t *testing.T) {
	t.Parallel()
	r := Report{Results: []Result{
		{Name: "X", Status: StatusOK, Message: "fine", Hint: "all good"},
		{Name: "Y", Status: StatusFail, Message: "broken"},
	}}
	plain := FormatText(r, false)
	if !strings.Contains(plain, "[ok]") || !strings.Contains(plain, "[fail]") {
		t.Errorf("missing labels in plain output:\n%s", plain)
	}
	tty := FormatText(r, true)
	if !strings.Contains(tty, "\033[32m") || !strings.Contains(tty, "\033[31m") {
		t.Errorf("tty output missing ANSI colors:\n%q", tty)
	}
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckSlack_Table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		URL         string
		WantStatus  Status
		WantMessage string
	}{{ // Test 0: Plain http scheme is rejected.
		URL:         "http://insecure.example/webhook",
		WantStatus:  StatusFail,
		WantMessage: "webhook URL must be https with a host: http",
	}, { // Test 1: https without a host is rejected.
		URL:         "https:///path",
		WantStatus:  StatusFail,
		WantMessage: "webhook URL must be https with a host: https",
	}, { // Test 2: Unparseable URL reports the parse error.
		URL:        "https://bad host/\x7f",
		WantStatus: StatusFail,
	}, { // Test 3: Empty URL is off.
		URL: "", WantStatus: StatusOff,
	}, { // Test 4: Valid https URL passes.
		URL:         "https://hooks.slack.com/services/a/b",
		WantStatus:  StatusOK,
		WantMessage: "URL parsed OK; pass --probe to send a test message",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := checkSlack(context.Background(), Options{SlackWebhookURL: test.URL})
			if diff := cmp.Diff(test.WantStatus, got.Status); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
			if strings.Contains(got.Message, "<nil>") {
				t.Errorf("message contains <nil>: %q", got.Message)
			}
			if test.WantMessage != "" {
				if diff := cmp.Diff(test.WantMessage, got.Message); diff != "" {
					t.Errorf("message mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestCheckGitHub_Probe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Body       string
		WantStatus Status
		Code       int
		Token      string
		Probe      bool
		Err        error
	}{{ // Test 0: Transport error fails.
		Err: errors.New("boom"), WantStatus: StatusFail,
	}, { // Test 1: Empty token is off.
		Token: "-", WantStatus: StatusOff,
	}, { // Test 2: Without probe a good token is OK.
		Token: "real-token-1234567890", WantStatus: StatusOK,
	}, { // Test 3: Short token fails.
		Token: "short", WantStatus: StatusFail, Probe: true,
	}, { // Test 4: 401 fails.
		Code: http.StatusUnauthorized, WantStatus: StatusFail,
	}, { // Test 5: 500 warns.
		Code: http.StatusInternalServerError, WantStatus: StatusWarn,
	}, { // Test 6: 200 with a bad body warns.
		Code: http.StatusOK, Body: "not json", WantStatus: StatusWarn,
	}, { // Test 7: 200 with a login is OK.
		Code: http.StatusOK, Body: `{"login":"x"}`, WantStatus: StatusOK,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			token, probe := "real-token-1234567890", true
			if test.Token != "" {
				token, probe = test.Token, test.Probe
			}
			if token == "-" {
				token = ""
			}
			client := &http.Client{Transport: roundTripperFunc(
				func(*http.Request) (*http.Response, error) {
					if test.Err != nil {
						return nil, test.Err
					}
					return &http.Response{
						StatusCode: test.Code,
						Status:     fmt.Sprintf("%d", test.Code),
						Body:       io.NopCloser(strings.NewReader(test.Body)),
						Header:     http.Header{},
					}, nil
				})}
			got := checkGitHub(context.Background(), Options{
				GitHubToken: token,
				Probe:       probe,
				HTTPClient:  client,
			})
			if diff := cmp.Diff(test.WantStatus, got.Status); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCheckSlack_ProbeFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Err        error
		WantStatus Status
		Code       int
	}{{ // Test 0: Transport error fails.
		Err: errors.New("boom"), WantStatus: StatusFail,
	}, { // Test 1: Non-2xx fails.
		Code: http.StatusBadRequest, WantStatus: StatusFail,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			client := &http.Client{Transport: roundTripperFunc(
				func(*http.Request) (*http.Response, error) {
					if test.Err != nil {
						return nil, test.Err
					}
					return &http.Response{
						StatusCode: test.Code,
						Status:     fmt.Sprintf("%d", test.Code),
						Body:       io.NopCloser(strings.NewReader("bad")),
						Header:     http.Header{},
					}, nil
				})}
			got := checkSlack(context.Background(), Options{
				SlackWebhookURL: "https://hooks.slack.com/services/a/b",
				Probe:           true,
				HTTPClient:      client,
			})
			if diff := cmp.Diff(test.WantStatus, got.Status); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCheckOTel(t *testing.T) {
	tests := []struct {
		Env        map[string]string
		WantStatus Status
	}{{ // Test 0: Nothing set is off.
		WantStatus: StatusOff,
	}, { // Test 1: Shared endpoint is OK.
		Env:        map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://x"},
		WantStatus: StatusOK,
	}, { // Test 2: Traces only is OK.
		Env:        map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://x"},
		WantStatus: StatusOK,
	}, { // Test 3: Metrics only is OK.
		Env:        map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://x"},
		WantStatus: StatusOK,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			for _, k := range []string{
				"OTEL_EXPORTER_OTLP_ENDPOINT",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
			} {
				t.Setenv(k, test.Env[k])
			}
			if diff := cmp.Diff(test.WantStatus, checkOTel().Status); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
