package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestOIDCHandlers_NotConfigured verifies the login and callback handlers
// report 404 when OIDC is not configured, and logout always redirects.
func TestOIDCHandlers_NotConfigured(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t) // oidc is nil in the default test server.

	login := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)
	lw := httptest.NewRecorder()
	srv.handleOIDCLogin(lw, login)
	if lw.Code != http.StatusNotFound {
		t.Errorf("login: want 404, got %d", lw.Code)
	}

	cb := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	cw := httptest.NewRecorder()
	srv.handleOIDCCallback(cw, cb)
	if cw.Code != http.StatusNotFound {
		t.Errorf("callback: want 404, got %d", cw.Code)
	}

	out := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	ow := httptest.NewRecorder()
	srv.handleOIDCLogout(ow, out)
	if ow.Code != http.StatusFound {
		t.Errorf("logout: want 302, got %d", ow.Code)
	}
}

// TestStringClaim covers the typed-claim extraction helper.
func TestStringClaim(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"email": "a@b.co", "count": 3}
	tests := []struct {
		Name       string
		Key        string
		WantResult string
	}{
		{Name: "present string", Key: "email", WantResult: "a@b.co"}, // Test 0.
		{Name: "missing key", Key: "sub", WantResult: ""},            // Test 1.
		{Name: "non-string", Key: "count", WantResult: ""},           // Test 2.
	}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := stringClaim(claims, test.Key); got != test.WantResult {
				t.Errorf("test %d: want %q, got %q", i, test.WantResult, got)
			}
		})
	}
}

// TestRandomState verifies the state generator returns distinct 32-byte
// base64url values.
func TestRandomState(t *testing.T) {
	t.Parallel()
	a, err := randomState()
	if err != nil {
		t.Fatalf("randomState: %v", err)
	}
	b, err := randomState()
	if err != nil {
		t.Fatalf("randomState: %v", err)
	}
	if a == b {
		t.Error("two calls should differ")
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("want 32 random bytes, got %d", len(raw))
	}
}

// TestPruneAuditOnce verifies a single retention pass removes rows older than
// the cutoff while keeping newer ones.
func TestPruneAuditOnce(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if err := ss.SaveAuditEntry(ctx, store.AuditEntry{
		Method: "POST", Path: "/old", Status: 200, Timestamp: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := ss.SaveAuditEntry(ctx, store.AuditEntry{
		Method: "POST", Path: "/new", Status: 200, Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("seed new: %v", err)
	}

	srv.pruneAuditOnce(ctx, time.Hour)

	entries, err := ss.ListAuditEntries(ctx, store.AuditListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "/new" {
		t.Errorf("expected only the recent entry to survive, got %+v", entries)
	}
}

// TestStartAuditRetention covers the disabled guard and the immediate first
// prune performed by the launched goroutine.
func TestStartAuditRetention(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)

	// retain <= 0 is a no-op and must not launch anything.
	srv.StartAuditRetention(context.Background(), 0)

	if err := ss.SaveAuditEntry(context.Background(), store.AuditEntry{
		Method: "POST", Path: "/stale", Status: 200, Timestamp: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.StartAuditRetention(ctx, time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := ss.ListAuditEntries(context.Background(), store.AuditListOptions{})
		if len(entries) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected the stale entry to be pruned by the retention goroutine")
}

// TestSelectScanners covers the all-scanners default and the allowlist filter.
func TestSelectScanners(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.registry.Register("fake", scanner.ScannerFunc(
		func(context.Context, *kube.Client) (scanner.Result, error) {
			return scanner.Result{Scanner: "fake"}, nil
		}))

	all := srv.selectScanners(nil)
	if _, ok := all["fake"]; !ok {
		t.Error("nil allowlist should return all registered scanners")
	}

	only := srv.selectScanners([]string{"fake"})
	if len(only) != 1 || only["fake"] == nil {
		t.Errorf("allowlist should return just the fake scanner, got %d", len(only))
	}

	none := srv.selectScanners([]string{"nonexistent"})
	if len(none) != 0 {
		t.Errorf("unknown scanner should yield empty set, got %d", len(none))
	}
}

// TestCountFindings covers severity totalling and the nil-report guard.
func TestCountFindings(t *testing.T) {
	t.Parallel()
	rpt := &report.Report{Findings: []report.Finding{
		{Severity: report.SeverityCritical},
		{Severity: report.SeverityWarning},
		{Severity: report.SeverityCritical},
	}}
	if got := countFindings(rpt, report.SeverityCritical); got != 2 {
		t.Errorf("critical: want 2, got %d", got)
	}
	if got := countFindings(rpt, report.SeverityWarning); got != 1 {
		t.Errorf("warning: want 1, got %d", got)
	}
	if got := countFindings(nil, report.SeverityCritical); got != 0 {
		t.Errorf("nil report: want 0, got %d", got)
	}
}

// TestResolveOptionContexts covers the group-expansion path, the direct
// contexts path, and the unknown-group error.
func TestResolveOptionContexts(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if err := ss.SaveGroup(ctx, "prod", []string{"east", "west"}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	got, err := srv.resolveOptionContexts(ctx, controller.ScanOptions{Group: "prod"})
	if err != nil {
		t.Fatalf("group path: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("group path: want 2 clusters, got %d", len(got))
	}

	direct, err := srv.resolveOptionContexts(ctx, controller.ScanOptions{Contexts: []string{"solo"}})
	if err != nil {
		t.Fatalf("direct path: %v", err)
	}
	if len(direct) != 1 || direct[0] != "solo" {
		t.Errorf("direct path: unexpected %v", direct)
	}

	if _, err := srv.resolveOptionContexts(ctx, controller.ScanOptions{Group: "ghost"}); err == nil {
		t.Error("unknown group should error")
	}
}

// TestFilterAckedFindings verifies findings with an active ack are dropped and
// the empty-input guard returns early.
func TestFilterAckedFindings(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()

	acked := report.Finding{Cluster: "east", Scanner: "version", Title: "old k8s"}
	fp := storeAckFingerprint(acked.Cluster, acked.Scanner, acked.Title)
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

// TestRecordScanDuration verifies the gauge stores the last scan duration.
func TestRecordScanDuration(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.recordScanDuration(1500 * time.Millisecond)
	if got := srv.lastScanDuration.Load(); got != int64(1500*time.Millisecond) {
		t.Errorf("want %d, got %d", int64(1500*time.Millisecond), got)
	}
}
