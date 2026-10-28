package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
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

// TestDedupCriticals_KeysOnRule verifies a count change in the title does not
// re-notify, because dedup keys on the rule, not the wording.
func TestDedupCriticals_KeysOnRule(t *testing.T) {
	t.Parallel()
	s := &Server{slackNotifiedKeys: map[string]time.Time{}}
	first := report.Finding{Cluster: "c", Scanner: "workload-security", Rule: "workload-security/privileged", Title: "c has 3 privileged container(s)", Severity: report.SeverityCritical}
	again := first
	again.Title = "c has 4 privileged container(s)"
	other := first
	other.Cluster = "x"
	if got := s.dedupCriticals([]report.Finding{first}); len(got) != 1 {
		t.Fatalf("first pass: want 1, got %d", len(got))
	}
	if got := s.dedupCriticals([]report.Finding{again, other}); len(got) != 1 || got[0].Cluster != "x" {
		t.Errorf("second pass: want only cluster x, got %+v", got)
	}
}

func TestBuildSlackPayload_Shape(t *testing.T) {
	t.Parallel()
	r := &report.Report{
		Clusters: []string{"a", "b"},
		FleetScore: report.FleetScore{
			Score:            73,
			Grade:            "C",
			Headline:         "two clusters",
			SampleSize:       2,
			Dimensions:       5,
			ExcludedClusters: 1,
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
	// The score block carries the score's provenance, not just its value.
	scoreText := ""
	if len(p.Blocks) > 1 && p.Blocks[1].Text != nil {
		scoreText = p.Blocks[1].Text.Text
	}
	for _, want := range []string{
		"scored from 2 clusters across 5 dimensions",
		"1 cluster excluded for insufficient data",
	} {
		if !strings.Contains(scoreText, want) {
			t.Errorf("score block missing %q: %s", want, scoreText)
		}
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
	findings := make([]report.Finding, 0, slackMaxFindingsPerPost+5)
	for i := range slackMaxFindingsPerPost + 5 {
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

// TestFilterAckedFindings verifies findings with an active ack are dropped and
// the empty-input guard returns early.
func TestFilterAckedFindings(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()

	acked := report.Finding{Cluster: "east", Scanner: "version", Rule: "version/skew", Title: "old k8s"}
	fp := report.FindingFingerprint(acked)
	if err := ss.SaveAck(ctx, store.AckRecord{
		Fingerprint: fp, Cluster: "east", Scanner: "version", Title: "old k8s",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed ack: %v", err)
	}
	live := report.Finding{Cluster: "west", Scanner: "metrics", Title: "cpu high"}

	got := srv.filterAckedFindings(ctx, []report.Finding{acked, live})
	if len(got) != 1 || got[0].Title != "cpu high" {
		t.Errorf("expected only the un-acked finding, got %+v", got)
	}

	if out := srv.filterAckedFindings(ctx, nil); out != nil {
		t.Errorf("empty input should return nil, got %+v", out)
	}
}
