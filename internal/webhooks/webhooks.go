// Package webhooks loads a YAML config of outbound HTTP subscribers and
// dispatches matching findings to each one after every scan. Acts as the
// generic version of the Slack notifier: same dedup window, same "no
// notification failure ever breaks a scan" stance, but configurable to fit
// any system that takes an HTTP POST.
package webhooks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"text/template"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// requestTimeout caps a single outbound POST. Subscribers run sequentially;
// the timeout matters because one slow target should not stall the next.
const requestTimeout = 6 * time.Second

// dedupTTL is how long a finding fingerprint counts as "already notified".
// Aligned with the Slack notifier so a finding deduped on one channel is
// also deduped on the others.
const dedupTTL = 6 * time.Hour

// Config is the YAML shape an operator supplies via --webhook-config.
type Config struct {
	// Webhooks lists outbound subscribers.
	Webhooks []Subscriber `json:"webhooks"`
}

// Subscriber is one outbound webhook target. Filters compose with AND.
type Subscriber struct {
	// Name labels the subscriber in logs.
	Name string `json:"name"`
	// URL is the POST target.
	URL string `json:"url"`
	// MinSeverity is critical, warning, or info. Findings below this are
	// dropped before any other matching takes place.
	MinSeverity string `json:"min_severity"`
	// ScannerRegex, when set, restricts to findings whose Scanner matches.
	ScannerRegex string `json:"scanner_regex,omitempty"`
	// ClusterRegex, when set, restricts to findings whose Cluster matches.
	ClusterRegex string `json:"cluster_regex,omitempty"`
	// Headers are added to every outbound request. Values are passed
	// through os.ExpandEnv so "$PAGERDUTY_TOKEN" is substituted from env.
	Headers map[string]string `json:"headers,omitempty"`
	// BodyTemplate is a Go text/template string evaluated per finding with
	// the Finding object plus a few helpers. Empty means a default JSON
	// envelope is sent.
	BodyTemplate string `json:"body_template,omitempty"`
	// ContentType is the value of the Content-Type header. Defaults to
	// application/json.
	ContentType string `json:"content_type,omitempty"`

	scannerRE *regexp.Regexp
	clusterRE *regexp.Regexp
	tmpl      *template.Template
}

// LoadConfig reads and validates a webhook config from path. Returns a
// zero-valued (no subscribers) config when path is empty so callers can
// pass through unset flags without an explicit nil check.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read webhook config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse webhook config: %w", err)
	}
	if err := compile(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// compile validates each subscriber and pre-compiles its regex and template
// so dispatch is allocation-light at scan time.
func compile(cfg *Config) error {
	for i := range cfg.Webhooks {
		s := &cfg.Webhooks[i]
		if s.URL == "" {
			return fmt.Errorf("webhook %q: url required", s.Name)
		}
		if s.MinSeverity == "" {
			s.MinSeverity = report.SeverityInfo
		}
		if s.ContentType == "" {
			s.ContentType = "application/json"
		}
		if s.ScannerRegex != "" {
			re, err := regexp.Compile(s.ScannerRegex)
			if err != nil {
				return fmt.Errorf("webhook %q: scanner_regex %q: %w", s.Name, s.ScannerRegex, err)
			}
			s.scannerRE = re
		}
		if s.ClusterRegex != "" {
			re, err := regexp.Compile(s.ClusterRegex)
			if err != nil {
				return fmt.Errorf("webhook %q: cluster_regex %q: %w", s.Name, s.ClusterRegex, err)
			}
			s.clusterRE = re
		}
		if s.BodyTemplate != "" {
			t, err := template.New(s.Name).Parse(s.BodyTemplate)
			if err != nil {
				return fmt.Errorf("webhook %q: body_template: %w", s.Name, err)
			}
			s.tmpl = t
		}
	}
	return nil
}

// Dispatcher is the per-server runtime that holds a Config plus a dedupe
// map keyed by subscriber + finding fingerprint, so the same critical does
// not get fired at every subscriber on every scan.
type Dispatcher struct {
	// cfg holds the parsed subscribers.
	cfg *Config
	// client is the HTTP client used for outbound POSTs.
	client *http.Client
	// log is the function called with non-fatal errors. Type matches the
	// minimal subset of zap.Logger we need so the package does not depend
	// on zap directly.
	log Logger

	mu       sync.Mutex
	notified map[string]time.Time
}

// Logger is the minimal logging surface the dispatcher needs. Compatible
// with zap.SugaredLogger and the standard log package via small wrappers.
type Logger interface {
	// Warnw logs a warning with the given message and key/value pairs.
	Warnw(msg string, keysAndValues ...any)
	// Infow logs an info message with the given key/value pairs.
	Infow(msg string, keysAndValues ...any)
}

// NoopLogger satisfies Logger and discards every message.
type NoopLogger struct{}

// Warnw implements Logger.Warnw and discards the message.
func (NoopLogger) Warnw(string, ...any) {}

// Infow implements Logger.Infow and discards the message.
func (NoopLogger) Infow(string, ...any) {}

// NewDispatcher returns a Dispatcher for cfg. cfg may be nil, in which case
// Dispatch is a no-op.
func NewDispatcher(cfg *Config, log Logger) *Dispatcher {
	if log == nil {
		log = NoopLogger{}
	}
	return &Dispatcher{
		cfg:      cfg,
		client:   &http.Client{Timeout: requestTimeout},
		log:      log,
		notified: map[string]time.Time{},
	}
}

// SetClient lets tests inject an httptest.Server's client.
func (d *Dispatcher) SetClient(c *http.Client) { d.client = c }

// Dispatch sends every matching, non-deduped finding to each subscriber.
// Subscribers run sequentially within one call so the order in the config
// file is the order operators see things hit the wire.
func (d *Dispatcher) Dispatch(ctx context.Context, findings []report.Finding) {
	if d == nil || d.cfg == nil || len(d.cfg.Webhooks) == 0 {
		return
	}
	now := time.Now()
	d.gcExpired(now)

	for _, s := range d.cfg.Webhooks {
		for _, f := range findings {
			if !matches(s, f) {
				continue
			}
			key := dedupKey(s.Name, f)
			d.mu.Lock()
			if _, seen := d.notified[key]; seen {
				d.mu.Unlock()
				continue
			}
			d.notified[key] = now
			d.mu.Unlock()

			if err := d.send(ctx, s, f); err != nil {
				d.log.Warnw("webhook send failed",
					"name", s.Name, "url", s.URL, "err", err)
			}
		}
	}
}

// matches returns whether the finding satisfies a subscriber's filters.
func matches(s Subscriber, f report.Finding) bool {
	if !severityAtLeast(f.Severity, s.MinSeverity) {
		return false
	}
	if s.scannerRE != nil && !s.scannerRE.MatchString(f.Scanner) {
		return false
	}
	if s.clusterRE != nil && !s.clusterRE.MatchString(f.Cluster) {
		return false
	}
	return true
}

// severityRank assigns a numeric weight to each severity for comparison.
func severityRank(s string) int {
	switch s {
	case report.SeverityCritical:
		return 3
	case report.SeverityWarning:
		return 2
	case report.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// severityAtLeast reports whether got meets the want threshold.
func severityAtLeast(got, want string) bool {
	return severityRank(got) >= severityRank(want)
}

// dedupKey is the fingerprint used to suppress repeat notifications. Scoped
// per subscriber so different subscribers can each fire once on the same
// finding without colliding.
func dedupKey(subscriber string, f report.Finding) string {
	h := sha256.New()
	h.Write([]byte(subscriber))
	h.Write([]byte{0})
	h.Write([]byte(f.Cluster))
	h.Write([]byte{0})
	h.Write([]byte(f.Scanner))
	h.Write([]byte{0})
	h.Write([]byte(f.Title))
	return hex.EncodeToString(h.Sum(nil))
}

// gcExpired drops dedup entries older than dedupTTL.
func (d *Dispatcher) gcExpired(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.notified {
		if now.Sub(t) > dedupTTL {
			delete(d.notified, k)
		}
	}
}

// send renders and posts one finding to one subscriber.
func (d *Dispatcher) send(ctx context.Context, s Subscriber, f report.Finding) error {
	body, err := renderBody(s, f)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", s.ContentType)
	for k, v := range s.Headers {
		req.Header.Set(k, os.ExpandEnv(v))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx: %s", resp.Status)
	}
	d.log.Infow("webhook delivered",
		"name", s.Name, "severity", f.Severity, "cluster", f.Cluster)
	return nil
}

// renderBody returns the request body for one finding. When the subscriber
// has no template, a default JSON envelope is produced. Templates have
// access to the Finding plus an Env helper for environment variables.
func renderBody(s Subscriber, f report.Finding) ([]byte, error) {
	if s.tmpl == nil {
		// Default envelope: minimal JSON the receiver can parse without a
		// schema.
		out, err := yaml.Marshal(map[string]any{
			"severity":    f.Severity,
			"cluster":     f.Cluster,
			"scanner":     f.Scanner,
			"title":       f.Title,
			"description": f.Description,
			"affected":    f.Affected,
			"remediation": f.Remediation,
		})
		if err != nil {
			return nil, err
		}
		return yamlToJSON(out)
	}
	var buf bytes.Buffer
	data := map[string]any{
		"Severity":    f.Severity,
		"Cluster":     f.Cluster,
		"Scanner":     f.Scanner,
		"Title":       f.Title,
		"Description": f.Description,
		"Affected":    f.Affected,
		"Remediation": f.Remediation,
		"Env":         envMap,
	}
	if err := s.tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	// Expand any literal $VAR in the rendered output. Operators frequently
	// drop env-style placeholders into template bodies; expanding here
	// keeps the templates legible.
	return []byte(os.ExpandEnv(buf.String())), nil
}

// envMap is a template func returning a value from the environment.
var envMap = func(k string) string { return os.Getenv(k) }

// yamlToJSON converts a YAML-marshalled byte slice into JSON. We round-trip
// through sigs.k8s.io/yaml so the default body is valid JSON.
func yamlToJSON(in []byte) ([]byte, error) {
	out, err := yaml.YAMLToJSON(in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrInvalidConfig is returned by LoadConfig when the YAML is unparseable.
var ErrInvalidConfig = errors.New("invalid webhook config")
