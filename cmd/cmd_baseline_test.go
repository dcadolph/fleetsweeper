package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// seedBaselineStore writes a single scan whose image-audit and
// workload-security results produce a fully-populated baseline.
func seedBaselineStore(t *testing.T, dbPath string) {
	t.Helper()
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	results := map[string]map[string]scanner.Result{
		"prod": {
			"image-audit": {
				Scanner: "image-audit",
				Data: map[string]any{
					"total_containers": 100,
					"no_digest":        10,
				},
			},
			"workload-security": {
				Scanner: "workload-security",
				Data: map[string]any{
					"total_pods":                   40,
					"run_as_root_containers":       10,
					"allow_privilege_escalation":   5,
					"no_read_only_root":            20,
					"default_service_account_pods": 4,
				},
			},
		},
	}
	if _, err := s.SaveScan(ctx, []string{"prod"}, results); err != nil {
		t.Fatalf("save scan: %v", err)
	}
}

// runBaseline executes the baseline subcommand with the given arguments
// against a temp database, returning captured stdout.
func runBaseline(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"baseline"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestBaselineShow verifies the YAML output reflects the seeded scan.
func TestBaselineShow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "show.db")
	seedBaselineStore(t, dbPath)

	out, err := runBaseline(t, dbPath, "show")
	if err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	var b admission.Baseline
	if err := yaml.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("yaml: %v\nout: %s", err, out)
	}
	if b.SampleContainers != 100 {
		t.Errorf("SampleContainers: want 100, got %d", b.SampleContainers)
	}
	if b.SamplePods != 40 {
		t.Errorf("SamplePods: want 40, got %d", b.SamplePods)
	}
	// 100 total, 10 missing digest = 90 pinned -> 0.9.
	if b.DigestPinFraction < 0.89 || b.DigestPinFraction > 0.91 {
		t.Errorf("DigestPinFraction: want ~0.9, got %v", b.DigestPinFraction)
	}
}

// TestBaselineExport verifies the export subcommand writes a YAML file
// that round-trips.
func TestBaselineExport(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "export.db")
	seedBaselineStore(t, dbPath)
	out := filepath.Join(dir, "baseline.yaml")

	if _, err := runBaseline(t, dbPath, "export", out); err != nil {
		t.Fatalf("export: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var b admission.Baseline
	if err := yaml.Unmarshal(body, &b); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if b.SampleContainers != 100 {
		t.Errorf("SampleContainers: want 100, got %d", b.SampleContainers)
	}
}

// TestBaselineDiffClean verifies diff returns no error when the saved
// baseline matches the current one within epsilon.
func TestBaselineDiffClean(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "diff.db")
	seedBaselineStore(t, dbPath)
	saved := filepath.Join(dir, "saved.yaml")
	if _, err := runBaseline(t, dbPath, "export", saved); err != nil {
		t.Fatalf("export: %v", err)
	}

	out, err := runBaseline(t, dbPath, "diff", saved)
	if err != nil {
		t.Fatalf("diff clean: %v\n%s", err, out)
	}
	if !strings.Contains(out, "digest_pin_fraction") {
		t.Errorf("expected diff table, got: %s", out)
	}
}

// TestBaselineDiffRegression verifies diff returns non-nil error when a
// saved fraction exceeds the epsilon threshold.
func TestBaselineDiffRegression(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "regress.db")
	seedBaselineStore(t, dbPath)

	// Saved baseline asserts a much higher digest pin fraction than the
	// scan supports (current is ~0.9; saved is 0.99).
	saved := admission.Baseline{
		SamplePods:        40,
		SampleContainers:  100,
		DigestPinFraction: 0.99,
	}
	body, err := yaml.Marshal(saved)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "saved.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := runBaseline(t, dbPath, "diff", "--epsilon=0.01", path); err == nil {
		t.Error("expected drift error, got nil")
	}
}
