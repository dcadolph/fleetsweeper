package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// newServerCheckCmd returns a command carrying the doctor server-probe flags.
func newServerCheckCmd(addr, token string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("addr", addr, "")
	cmd.Flags().String("token", token, "")
	return cmd
}

// TestDoctorCheckServer verifies skip, healthy, and failing probes.
func TestDoctorCheckServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test 0: No addr skips the check.
	if got := doctorCheckServer(ctx, newServerCheckCmd("", "")); got.Status != StatusSkip {
		t.Errorf("no addr: got %s, want skip", got.Status)
	}

	// Test 1: A server that answers 200 on both probes is healthy.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if got := doctorCheckServer(ctx, newServerCheckCmd(ok.URL, "secret")); got.Status != StatusOK {
		t.Errorf("healthy: got %s (%s), want ok", got.Status, got.Detail)
	}

	// Test 2: A server returning 500 fails the check.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if got := doctorCheckServer(ctx, newServerCheckCmd(bad.URL, "")); got.Status != StatusFail {
		t.Errorf("unhealthy: got %s, want fail", got.Status)
	}
}

// newFreshnessCmd returns a command carrying the scan-freshness flags.
func newFreshnessCmd(dbPath string, maxAge time.Duration) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("db", dbPath, "")
	cmd.Flags().String("db-driver", "", "")
	cmd.Flags().Duration("scan-freshness", maxAge, "")
	return cmd
}

// TestDoctorCheckScanFreshness verifies skip, warn, ok, and stale outcomes.
func TestDoctorCheckScanFreshness(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test 0: No db skips.
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd("", time.Hour)); got.Status != StatusSkip {
		t.Errorf("no db: got %s, want skip", got.Status)
	}

	// Test 1: Empty store warns.
	emptyPath := filepath.Join(t.TempDir(), "empty.db")
	if s, err := store.NewSQLite(emptyPath); err != nil {
		t.Fatalf("open empty: %v", err)
	} else {
		s.Close()
	}
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(emptyPath, time.Hour)); got.Status != StatusWarn {
		t.Errorf("empty store: got %s, want warn", got.Status)
	}

	// Test 2: A fresh scan within the window is ok.
	freshPath := filepath.Join(t.TempDir(), "fresh.db")
	seedHistoryScans(t, freshPath, 1)
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(freshPath, 24*time.Hour)); got.Status != StatusOK {
		t.Errorf("fresh scan: got %s (%s), want ok", got.Status, got.Detail)
	}

	// Test 3: A near-zero freshness window makes the same scan read as stale.
	if got := doctorCheckScanFreshness(ctx, newFreshnessCmd(freshPath, time.Nanosecond)); got.Status != StatusFail {
		t.Errorf("stale scan: got %s, want fail", got.Status)
	}
}
