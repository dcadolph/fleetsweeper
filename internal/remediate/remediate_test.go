package remediate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

func TestOpen_DryRun_NoNetwork(t *testing.T) {
	t.Parallel()
	f := report.Finding{
		Title:       "prod-east has no NetworkPolicy in payments",
		Description: "Default-deny policy missing.",
		Severity:    report.SeverityCritical,
		Cluster:     "prod-east",
		Scanner:     "network-policies",
		Remediation: &report.Remediation{
			Command: "kubectl apply -f -",
			YAML:    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n...",
		},
	}
	res, err := Open(context.Background(), Options{
		Owner: "dcadolph", Repo: "gitops",
		Cluster: "prod-east", Finding: f,
		Push: false,
	})
	if err != nil {
		t.Fatalf("dry-run unexpectedly errored: %v", err)
	}
	if !res.DryRun {
		t.Errorf("expected DryRun=true on plan")
	}
	if res.PlannedYAML == "" {
		t.Errorf("PlannedYAML should be populated even on dry run")
	}
	if !strings.HasPrefix(res.HeadBranch, "fleetsweeper/") {
		t.Errorf("HeadBranch slug not used: %s", res.HeadBranch)
	}
	if !strings.HasPrefix(res.TargetPath, "fleetsweeper/prod-east/") {
		t.Errorf("TargetPath unexpected: %s", res.TargetPath)
	}
	if res.PRURL != "" {
		t.Errorf("dry run should not produce a PR URL: %s", res.PRURL)
	}
}

func TestOpen_NoYAML_ReturnsErr(t *testing.T) {
	t.Parallel()
	f := report.Finding{
		Title:       "x",
		Severity:    report.SeverityWarning,
		Remediation: nil,
	}
	_, err := Open(context.Background(), Options{Owner: "a", Repo: "b", Finding: f})
	if !errors.Is(err, ErrNoYAML) {
		t.Errorf("want ErrNoYAML, got %v", err)
	}
}

func TestOpen_MissingOwner(t *testing.T) {
	t.Parallel()
	f := report.Finding{Remediation: &report.Remediation{YAML: "x"}}
	if _, err := Open(context.Background(), Options{Finding: f}); err == nil {
		t.Errorf("expected error on missing owner")
	}
}

func TestOpen_Push_GitHubFlow(t *testing.T) {
	t.Parallel()
	var (
		calledGetRepo int32
		calledGetRef  int32
		calledPostRef int32
		calledPut     int32
		calledPullsP  int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calledGetRepo, 1)
		_ = json.NewEncoder(w).Encode(repoInfo{DefaultBranch: "main"})
	})
	mux.HandleFunc("/repos/o/r/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calledGetRef, 1)
		_ = json.NewEncoder(w).Encode(refInfo{Object: struct {
			SHA string `json:"sha"`
		}{SHA: "deadbeef"}})
	})
	mux.HandleFunc("/repos/o/r/git/refs", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calledPostRef, 1)
		var p createRefPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		if p.SHA != "deadbeef" {
			t.Errorf("createRef SHA mismatch: %+v", p)
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/repos/o/r/contents/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calledPut, 1)
		var p putFilePayload
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		dec, err := base64.StdEncoding.DecodeString(p.Content)
		if err != nil || string(dec) == "" {
			t.Errorf("content not properly base64 encoded: %v / %q", err, p.Content)
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calledPullsP, 1)
		var p prPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		if p.Base != "main" {
			t.Errorf("PR base wrong: %s", p.Base)
		}
		_ = json.NewEncoder(w).Encode(prResponse{
			HTMLURL: "https://github.com/o/r/pull/42",
			Number:  42,
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	f := report.Finding{
		Title:       "missing NetworkPolicy",
		Severity:    report.SeverityCritical,
		Scanner:     "network-policies",
		Remediation: &report.Remediation{YAML: "kind: NetworkPolicy\n"},
	}
	res, err := Open(context.Background(), Options{
		Owner: "o", Repo: "r", Cluster: "prod", Finding: f,
		Push: true, Token: "fake-token", BaseURL: ts.URL,
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("Open push: %v", err)
	}
	if res.PRURL != "https://github.com/o/r/pull/42" {
		t.Errorf("PR URL: got %s", res.PRURL)
	}
	if res.PRNumber != 42 {
		t.Errorf("PR number: got %d", res.PRNumber)
	}
	if calledGetRepo == 0 || calledGetRef == 0 || calledPostRef == 0 ||
		calledPut == 0 || calledPullsP == 0 {
		t.Errorf("not all expected endpoints called: repo=%d ref=%d postRef=%d put=%d pulls=%d",
			calledGetRepo, calledGetRef, calledPostRef, calledPut, calledPullsP)
	}
}

func TestSlugify(t *testing.T) {
	t.Parallel()
	cases := []struct{ In, Want string }{
		{"NodeReady: false", "nodeready-false"},
		{"  multi  spaces  ", "multi-spaces"},
		{"", "finding"},
		{strings.Repeat("a", 80), strings.Repeat("a", 60)},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := slugify(c.In); got != c.Want {
				t.Errorf("slugify(%q): want %q, got %q", c.In, c.Want, got)
			}
		})
	}
}

func TestRenderPRBody_IncludesContext(t *testing.T) {
	t.Parallel()
	f := report.Finding{
		Title:       "X",
		Description: "Y",
		Severity:    report.SeverityCritical,
		Scanner:     "Z",
		Affected:    []string{"pod-1"},
		Remediation: &report.Remediation{
			Command:    "kubectl apply -f -",
			YAML:       "...",
			RunbookURL: "https://runbook.example.com",
		},
	}
	body := renderPRBody(f, "prod-east", "fleetsweeper/prod-east/x.yaml")
	for _, want := range []string{
		"prod-east", "critical", "Z", "Y", "kubectl apply -f -",
		"pod-1", "runbook.example.com",
		"fleetsweeper/prod-east/x.yaml",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n---\n%s", want, body)
		}
	}
}
