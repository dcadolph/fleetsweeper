package server

import (
	"context"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestSelectScanners covers the all-scanners default and the allowlist filter.
func TestSelectScanners(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.registry.Register("fake", scanner.Func(
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
