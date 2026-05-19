package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

func TestFilterCriticals(t *testing.T) {
	t.Parallel()
	in := []report.Finding{
		{Severity: report.SeverityCritical, Title: "a"},
		{Severity: report.SeverityWarning, Title: "b"},
		{Severity: report.SeverityCritical, Title: "c"},
		{Severity: report.SeverityInfo, Title: "d"},
	}
	got := filterCriticals(in)
	if len(got) != 2 {
		t.Fatalf("want 2 criticals, got %d", len(got))
	}
	if got[0].Title != "a" || got[1].Title != "c" {
		t.Errorf("filter preserved wrong findings: %+v", got)
	}
}

func TestDedupCriticals_FiltersRepeat(t *testing.T) {
	t.Parallel()
	s := &Server{slackNotifiedKeys: map[string]time.Time{}}
	findings := []report.Finding{
		{Severity: report.SeverityCritical, Cluster: "c1", Scanner: "s1", Title: "t1"},
		{Severity: report.SeverityCritical, Cluster: "c2", Scanner: "s1", Title: "t1"},
	}
	first := s.dedupCriticals(findings)
	if len(first) != 2 {
		t.Fatalf("first pass: want 2, got %d", len(first))
	}
	second := s.dedupCriticals(findings)
	if len(second) != 0 {
		t.Fatalf("second pass: want 0 (all deduped), got %d", len(second))
	}
}

func TestFindingFingerprint_Stable(t *testing.T) {
	t.Parallel()
	a := report.Finding{Cluster: "c", Scanner: "s", Title: "t"}
	b := report.Finding{Cluster: "c", Scanner: "s", Title: "t"}
	if findingFingerprint(a) != findingFingerprint(b) {
		t.Errorf("fingerprint not stable for identical findings")
	}
	if findingFingerprint(a) == findingFingerprint(report.Finding{Cluster: "x", Scanner: "s", Title: "t"}) {
		t.Errorf("fingerprint collided across clusters")
	}
}

func TestBuildSlackPayload_Shape(t *testing.T) {
	t.Parallel()
	r := &report.Report{
		Clusters: []string{"a", "b"},
		FleetScore: report.FleetScore{
			Score:    73,
			Grade:    "C",
			Headline: "two clusters",
		},
	}
	findings := []report.Finding{
		{Severity: report.SeverityCritical, Cluster: "a", Scanner: "node-health", Title: "node down",
			Remediation: &report.Remediation{Command: "kubectl --context a get nodes"}},
	}
	p := buildSlackPayload(findings, r)
	if p.Text == "" {
		t.Errorf("payload text is empty")
	}
	if len(p.Blocks) < 4 {
		t.Errorf("expected at least header+score+divider+finding blocks; got %d", len(p.Blocks))
	}
	// Round-trip through JSON to confirm encodability.
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) == 0 {
		t.Errorf("empty marshaled body")
	}
}

func TestBuildSlackPayload_TruncatesAtLimit(t *testing.T) {
	t.Parallel()
	r := &report.Report{Clusters: []string{"a"}}
	var findings []report.Finding
	for i := 0; i < slackMaxFindingsPerPost+5; i++ {
		findings = append(findings, report.Finding{
			Severity: report.SeverityCritical,
			Cluster:  "a",
			Scanner:  "s",
			Title:    fmt.Sprintf("t%d", i),
		})
	}
	p := buildSlackPayload(findings, r)
	// header + score + divider + N findings + "+ M more" section
	want := 3 + slackMaxFindingsPerPost + 1
	if len(p.Blocks) != want {
		t.Errorf("blocks: want %d, got %d", want, len(p.Blocks))
	}
}

func TestSlackEscape(t *testing.T) {
	t.Parallel()
	got := slackEscape("<script> & </script>")
	want := "&lt;script&gt; &amp; &lt;/script&gt;"
	if got != want {
		t.Errorf("escape: want %q, got %q", want, got)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	cases := []struct{ In, Want string; N int }{
		{"hello", "hello", 10},
		{"hello world", "hello...", 5},
		{"", "", 5},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := truncate(c.In, c.N); got != c.Want {
				t.Errorf("truncate(%q,%d): want %q, got %q", c.In, c.N, c.Want, got)
			}
		})
	}
}

func TestNotifySlackForReport_EndToEnd_Mocked(t *testing.T) {
	t.Parallel()
	var got atomic.Int32
	body := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body <- b
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Server{
		log:               zap.NewNop(),
		slackWebhookURL:   ts.URL,
		slackNotifiedKeys: map[string]time.Time{},
		slackMu:           sync.Mutex{},
	}
	r := &report.Report{
		Clusters: []string{"a"},
		Findings: []report.Finding{{
			Severity: report.SeverityCritical, Cluster: "a", Scanner: "s", Title: "t",
		}},
	}
	s.notifySlackForReport(context.Background(), r)
	select {
	case b := <-body:
		if len(b) == 0 {
			t.Errorf("empty body posted")
		}
	default:
		t.Errorf("no request received")
	}
	if got.Load() != 1 {
		t.Errorf("want 1 post, got %d", got.Load())
	}
	// Second call with same finding: dedup should suppress.
	s.notifySlackForReport(context.Background(), r)
	if got.Load() != 1 {
		t.Errorf("dedup failed; want 1 post total, got %d", got.Load())
	}
}
