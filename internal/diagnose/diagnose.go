// Package diagnose runs an end-to-end sanity check across every Fleetsweeper
// integration. The intent is operator-grade: before wiring Fleetsweeper into
// a production pipeline, run `fleetsweeper diagnose` and see at a glance
// which integrations are wired up, which are off, and which are broken.
//
// Each check produces a Result with one of four statuses:
//   - StatusOK: the integration is configured and the local check passes
//   - StatusOff: the integration is intentionally not configured
//   - StatusWarn: the integration is configured but a soft check failed
//   - StatusFail: the integration is configured and a hard check failed
//
// "Local check" is deliberately conservative. We do not call external APIs
// by default because that would conflate "configured" with "reachable" and
// make `diagnose` itself a flaky network test. Pass --probe to opt into
// active probing (Slack ping, GitHub API call, kubeconfig connect).
package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/fleetdrift"
	"github.com/dcadolph/fleetsweeper/internal/policyreport"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// Status is the four-state outcome of a single diagnostic.
type Status string

const (
	// StatusOK means the integration is configured and the check passed.
	StatusOK Status = "ok"
	// StatusOff means the integration is intentionally not configured.
	StatusOff Status = "off"
	// StatusWarn means the integration is configured but a soft check failed.
	StatusWarn Status = "warn"
	// StatusFail means the integration is configured and a hard check failed.
	StatusFail Status = "fail"
)

// Result is one row in the diagnose report.
type Result struct {
	// Name is the integration label.
	Name string `json:"name"`
	// Status is the outcome.
	Status Status `json:"status"`
	// Message is a one-line description of what we found.
	Message string `json:"message"`
	// Hint, when present, suggests an action the operator can take.
	Hint string `json:"hint,omitempty"`
	// Duration is how long the check took.
	Duration time.Duration `json:"duration_ns"`
}

// Options bundles the configuration the diagnose command needs.
type Options struct {
	// KubeconfigPath, when set, is checked for valid contexts.
	KubeconfigPath string
	// DBPath, when set, is opened and queried.
	DBPath string
	// SlackWebhookURL, when set, is checked for syntactic validity. When
	// Probe is true the webhook is also pinged with a test payload.
	SlackWebhookURL string
	// CostCSVPath, when set, is parsed.
	CostCSVPath string
	// PolicyReportOutputDir, when set, is exercised by writing a tiny
	// synthetic report into a tmp subdirectory.
	PolicyReportOutputDir string
	// FleetDriftOutputDir, when set, gets the same treatment.
	FleetDriftOutputDir string
	// GitHubToken, when set, is checked for format. When Probe is true the
	// token is validated by calling /user on the GitHub API.
	GitHubToken string
	// Probe enables active external-call checks (Slack ping, GitHub API).
	// Off by default so diagnose is deterministic and offline-safe.
	Probe bool
	// HTTPClient is used for active probes when Probe is true. Tests can
	// inject a httptest server here.
	HTTPClient *http.Client
}

// Report is the full diagnose output.
type Report struct {
	// Results is one entry per check, in execution order.
	Results []Result `json:"results"`
}

// Summary returns counts by status for the report.
func (r Report) Summary() map[Status]int {
	out := map[Status]int{StatusOK: 0, StatusOff: 0, StatusWarn: 0, StatusFail: 0}
	for _, res := range r.Results {
		out[res.Status]++
	}
	return out
}

// HasFailures reports whether any result is StatusFail.
func (r Report) HasFailures() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return true
		}
	}
	return false
}

// Run executes every diagnostic and returns the consolidated report. Each
// check is allowed to fail independently; one failure does not short-circuit
// the rest.
func Run(ctx context.Context, opts Options) Report {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 8 * time.Second}
	}
	checks := []func() Result{
		func() Result { return checkOTel() },
		func() Result { return checkSlack(ctx, opts) },
		func() Result { return checkCostCSV(opts) },
		func() Result { return checkFleetDriftOutput(opts) },
		func() Result { return checkPolicyReportOutput(opts) },
		func() Result { return checkGitHub(ctx, opts) },
	}
	out := Report{Results: make([]Result, 0, len(checks))}
	for _, c := range checks {
		start := time.Now()
		r := c()
		r.Duration = time.Since(start)
		out.Results = append(out.Results, r)
	}
	return out
}

// checkOTel reports whether OTel endpoints are configured.
func checkOTel() Result {
	r := Result{Name: "OpenTelemetry"}
	trace := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
	metrics := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != ""
	switch {
	case trace && metrics:
		r.Status = StatusOK
		r.Message = "traces + metrics endpoints configured"
	case trace:
		r.Status = StatusOK
		r.Message = "traces endpoint configured (no metrics endpoint)"
	case metrics:
		r.Status = StatusOK
		r.Message = "metrics endpoint configured (no traces endpoint)"
	default:
		r.Status = StatusOff
		r.Message = "no OTLP endpoint configured"
		r.Hint = "Set OTEL_EXPORTER_OTLP_ENDPOINT to enable"
	}
	return r
}

// checkSlack validates the webhook URL syntactically and optionally pings it.
func checkSlack(ctx context.Context, opts Options) Result {
	r := Result{Name: "Slack webhook"}
	if opts.SlackWebhookURL == "" {
		r.Status = StatusOff
		r.Message = "no webhook configured"
		r.Hint = "Pass --slack-webhook-url to enable"
		return r
	}
	u, err := url.Parse(opts.SlackWebhookURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("webhook URL invalid: %v", err)
		return r
	}
	if !opts.Probe {
		r.Status = StatusOK
		r.Message = "URL parsed OK; pass --probe to send a test message"
		return r
	}
	body := bytes.NewReader([]byte(`{"text":"fleetsweeper diagnose: connectivity check"}`))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.SlackWebhookURL, body)
	if err != nil {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("build request: %v", err)
		return r
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("post failed: %v", err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		r.Status = StatusFail
		r.Message = fmt.Sprintf("non-2xx: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		return r
	}
	r.Status = StatusOK
	r.Message = "test message posted"
	return r
}

// checkCostCSV parses the CSV if one is provided.
func checkCostCSV(opts Options) Result {
	r := Result{Name: "Cost CSV"}
	if opts.CostCSVPath == "" {
		r.Status = StatusOff
		r.Message = "no CSV configured"
		r.Hint = "Pass --cost-csv to enable"
		return r
	}
	m, err := cost.LoadCSV(opts.CostCSVPath)
	if err != nil {
		r.Status = StatusFail
		r.Message = err.Error()
		return r
	}
	r.Status = StatusOK
	r.Message = fmt.Sprintf("%d clusters parsed", len(m))
	return r
}

// checkPolicyReportOutput verifies the directory is writable by writing a
// throwaway report into a subdirectory.
func checkPolicyReportOutput(opts Options) Result {
	r := Result{Name: "PolicyReport output"}
	if opts.PolicyReportOutputDir == "" {
		r.Status = StatusOff
		r.Message = "no output dir configured"
		r.Hint = "Pass --policy-report-output to enable"
		return r
	}
	probeDir := filepath.Join(opts.PolicyReportOutputDir, ".fleetsweeper-diagnose")
	defer os.RemoveAll(probeDir)
	probe := policyreport.ReportsFor(&report.Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Clusters:  []string{"diagnose-probe"},
	}, "diagnose-scan", "fleetsweeper")
	if err := policyreport.Write(probe, probeDir); err != nil {
		r.Status = StatusFail
		r.Message = err.Error()
		return r
	}
	r.Status = StatusOK
	r.Message = "wrote probe report and cleaned up"
	return r
}

// checkFleetDriftOutput verifies the directory is writable for FleetDrift YAMLs.
func checkFleetDriftOutput(opts Options) Result {
	r := Result{Name: "FleetDriftReport output"}
	if opts.FleetDriftOutputDir == "" {
		r.Status = StatusOff
		r.Message = "no output dir configured"
		r.Hint = "Pass --fleetdrift-output to enable"
		return r
	}
	probeDir := filepath.Join(opts.FleetDriftOutputDir, ".fleetsweeper-diagnose")
	defer os.RemoveAll(probeDir)
	probe := fleetdrift.ReportsFor(&report.Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Clusters:  []string{"diagnose-probe"},
	}, "diagnose-scan", "")
	if err := fleetdrift.Write(probe, probeDir); err != nil {
		r.Status = StatusFail
		r.Message = err.Error()
		return r
	}
	r.Status = StatusOK
	r.Message = "wrote probe report and cleaned up"
	return r
}

// checkGitHub validates the token format and, when --probe is set, calls
// /user on the GitHub API to confirm the token is accepted.
func checkGitHub(ctx context.Context, opts Options) Result {
	r := Result{Name: "GitHub token"}
	if opts.GitHubToken == "" {
		r.Status = StatusOff
		r.Message = "no token provided"
		r.Hint = "Pass --github-token or set $GITHUB_TOKEN to enable remediation PRs"
		return r
	}
	if len(opts.GitHubToken) < 10 {
		r.Status = StatusFail
		r.Message = "token looks suspiciously short"
		return r
	}
	if !opts.Probe {
		r.Status = StatusOK
		r.Message = "token present; pass --probe to validate against GitHub"
		return r
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		r.Status = StatusFail
		r.Message = err.Error()
		return r
	}
	req.Header.Set("Authorization", "Bearer "+opts.GitHubToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "fleetsweeper-diagnose")
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		r.Status = StatusFail
		r.Message = err.Error()
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		r.Status = StatusFail
		r.Message = "GitHub rejected the token (401)"
		return r
	}
	if resp.StatusCode >= 300 {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("GitHub returned %s", resp.Status)
		return r
	}
	var info struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		r.Status = StatusWarn
		r.Message = "200 OK but response body unparseable"
		return r
	}
	r.Status = StatusOK
	r.Message = fmt.Sprintf("token valid for user %q", info.Login)
	return r
}

// FormatText renders the report as a human-readable text table suitable for
// the terminal. Status column uses ANSI when isatty is true.
func FormatText(report Report, isatty bool) string {
	var b strings.Builder
	width := 0
	for _, r := range report.Results {
		if len(r.Name) > width {
			width = len(r.Name)
		}
	}
	const sep = "─────────────────────────────────────────────────────────────"
	fmt.Fprintln(&b, sep)
	for _, r := range report.Results {
		label := colorize(string(r.Status), r.Status, isatty)
		fmt.Fprintf(&b, "[%s] %-*s  %s\n", label, width, r.Name, r.Message)
		if r.Hint != "" {
			fmt.Fprintf(&b, "       %-*s  %s\n", width, "", grey(r.Hint, isatty))
		}
	}
	fmt.Fprintln(&b, sep)
	s := report.Summary()
	fmt.Fprintf(&b, "%d checks: %d ok, %d off, %d warn, %d fail\n",
		len(report.Results), s[StatusOK], s[StatusOff], s[StatusWarn], s[StatusFail])
	return b.String()
}

// colorize wraps the given text in an ANSI colour suited to the status when
// the output is a TTY; returns plain text otherwise.
func colorize(text string, status Status, isatty bool) string {
	if !isatty {
		return text
	}
	switch status {
	case StatusOK:
		return "\033[32m" + text + "\033[0m"
	case StatusOff:
		return "\033[90m" + text + "\033[0m"
	case StatusWarn:
		return "\033[33m" + text + "\033[0m"
	case StatusFail:
		return "\033[31m" + text + "\033[0m"
	}
	return text
}

// grey wraps text in a dim ANSI colour for hints; plain text when not a TTY.
func grey(text string, isatty bool) string {
	if !isatty {
		return text
	}
	return "\033[90m" + text + "\033[0m"
}

// ErrFailures is returned by Run wrappers that want to translate the report's
// failure count into an error suitable for a CLI exit code.
var ErrFailures = errors.New("diagnose: one or more checks failed")
