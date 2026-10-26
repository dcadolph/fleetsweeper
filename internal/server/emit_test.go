package server

import (
	"os"
	"testing"
)

// TestWriteFleetDriftIfConfigured covers the no-op guards and the write path
// into a configured output directory.
func TestWriteFleetDriftIfConfigured(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	// No-op when unconfigured.
	srv.fleetDriftOutputDir = ""
	srv.writeFleetDriftIfConfigured(demoTestReport(), "scan-1")

	// No-op on a nil report even when configured.
	srv.fleetDriftOutputDir = t.TempDir()
	srv.writeFleetDriftIfConfigured(nil, "scan-1")
	if entries, _ := os.ReadDir(srv.fleetDriftOutputDir); len(entries) != 0 {
		t.Errorf("nil report should write nothing, got %d files", len(entries))
	}

	// Write path produces at least one file for the demo report.
	dir := t.TempDir()
	srv.fleetDriftOutputDir = dir
	srv.writeFleetDriftIfConfigured(demoTestReport(), "scan-2")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected fleetdrift files to be written")
	}
}

// TestWritePolicyReportIfConfigured covers the no-op guards and the write path
// into a configured output directory.
func TestWritePolicyReportIfConfigured(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)

	srv.policyReportOutputDir = ""
	srv.writePolicyReportIfConfigured(demoTestReport(), "scan-1")

	dir := t.TempDir()
	srv.policyReportOutputDir = dir
	srv.policyReportNamespace = "fleetsweeper"
	srv.writePolicyReportIfConfigured(nil, "scan-1")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("nil report should write nothing, got %d files", len(entries))
	}

	srv.writePolicyReportIfConfigured(demoTestReport(), "scan-2")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected policyreport files to be written")
	}
}

// TestDispatchWebhooks_NoopWhenUnconfigured verifies the dispatcher guard
// returns without panicking when no subscribers are configured.
func TestDispatchWebhooks_NoopWhenUnconfigured(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookDispatcher = nil
	// Should be a safe no-op with both a real and a nil report.
	srv.dispatchWebhooksIfConfigured(t.Context(), demoTestReport())
	srv.dispatchWebhooksIfConfigured(t.Context(), nil)
}
