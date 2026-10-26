package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/seal"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// exportScanTime is the fixed past timestamp seedExportScan stores, so a test can tell the
// scan's time apart from the time the export ran.
var exportScanTime = time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC) //nolint:gochecknoglobals // Not modified, simplifies testing.

// exportScanResults returns the scanner results seedExportScan stores.
func exportScanResults() map[string]map[string]scanner.Result {
	return map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
		"cluster-b": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.5"}}},
		"cluster-c": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
}

// seedExportScan stores one scan with a fixed ID at exportScanTime in a new SQLite database
// and returns the database path and the scan ID.
func seedExportScan(t *testing.T) (string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "export.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	id, err := s.SaveScanRecord(context.Background(), store.ScanRecord{
		ID:        "scan-export-1",
		Timestamp: exportScanTime,
		Clusters:  []string{"cluster-a", "cluster-b", "cluster-c"},
	}, exportScanResults())
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	return dbPath, id
}

// exportToFile runs export against dbPath into a new file and returns the bundle bytes.
func exportToFile(t *testing.T, dbPath string, args ...string) ([]byte, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := execExport(t, dbPath, append([]string{"--output=" + out}, args...)...); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return data, nil
}

// readExport parses bundle bytes with seal.ReadBundle.
func readExport(t *testing.T, data []byte) (string, map[string][]byte) {
	t.Helper()
	root, files, err := seal.ReadBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return root, files
}

// TestExportDeterministic verifies that exporting one scan twice gives byte-identical bundles,
// that report.json carries the scan's time rather than the export's, and that the bundle's
// signature equals the one the seal endpoint computes for the same scan.
func TestExportDeterministic(t *testing.T) {
	const key = "audit-key"
	dbPath, id := seedExportScan(t)

	first, err := exportToFile(t, dbPath, "--seal-key="+key)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	second, err := exportToFile(t, dbPath, "--seal-key="+key)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("two exports of one scan differ")
	}

	root, files := readExport(t, first)
	if diff := cmp.Diff("fleetsweeper-export-"+id, root); diff != "" {
		t.Errorf("root mismatch (-want +got):\n%s", diff)
	}
	if !bytes.Contains(files["report.json"], []byte(`"timestamp":"2026-03-01T12:30:00Z"`)) {
		t.Errorf("report.json does not carry the scan time:\n%.300s", files["report.json"])
	}
	if !bytes.Contains(files["scan_results.json"], []byte("v1.30.5")) {
		t.Error("scan_results.json does not carry the raw results")
	}

	rpt := report.Build([]string{"cluster-a", "cluster-b", "cluster-c"}, exportScanResults(),
		report.BuildOptions{Timestamp: exportScanTime})
	want, err := seal.BundleFiles(rpt, exportScanResults(), id, seal.BundleOptions{Sealed: true})
	if err != nil {
		t.Fatalf("bundle files: %v", err)
	}
	wantSig, err := seal.SealBundle(want, key)
	if err != nil {
		t.Fatalf("seal bundle: %v", err)
	}
	if diff := cmp.Diff(wantSig+"\n", string(files[seal.FileName])); diff != "" {
		t.Errorf("export signature differs from the endpoint's (-want +got):\n%s", diff)
	}
	if err := seal.VerifyBundle(files, key); err != nil {
		t.Errorf("verify exported bundle: %v", err)
	}
}

// TestExportUnsealed verifies that an export without a seal key carries no MANIFEST or
// signature and says so in METADATA.txt.
func TestExportUnsealed(t *testing.T) {
	dbPath, _ := seedExportScan(t)
	data, err := exportToFile(t, dbPath)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	_, files := readExport(t, data)
	for _, name := range []string{seal.ManifestFile, seal.FileName} {
		if _, ok := files[name]; ok {
			t.Errorf("unsealed export contains %s", name)
		}
	}
	if !bytes.Contains(files["METADATA.txt"], []byte("Sealed:        false")) {
		t.Errorf("METADATA.txt does not record an unsealed bundle:\n%s", files["METADATA.txt"])
	}
	if err := seal.VerifyBundle(files, "k"); !errors.Is(err, seal.ErrUnsealed) {
		t.Errorf("verify unsealed: want ErrUnsealed, got %v", err)
	}
}

// TestExportCostCSV verifies that a readable cost CSV lands in the bundle and the manifest,
// and that a missing or malformed one is an error rather than a silently smaller bundle.
func TestExportCostCSV(t *testing.T) {
	dbPath, _ := seedExportScan(t)

	csvPath := filepath.Join(t.TempDir(), "cost.csv")
	if err := os.WriteFile(csvPath, []byte("cluster,period,cost_usd\ncluster-a,2026-02,1200\ncluster-b,2026-02,800\n"), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	data, err := exportToFile(t, dbPath, "--cost-csv="+csvPath, "--seal-key=k")
	if err != nil {
		t.Fatalf("export with cost: %v", err)
	}
	_, files := readExport(t, data)
	if _, ok := files["cost.json"]; !ok {
		t.Error("cost.json missing from bundle")
	}
	if !bytes.Contains(files[seal.ManifestFile], []byte("  cost.json\n")) {
		t.Errorf("MANIFEST does not list cost.json:\n%s", files[seal.ManifestFile])
	}

	if _, err := exportToFile(t, dbPath, "--cost-csv="+filepath.Join(t.TempDir(), "absent.csv")); err == nil {
		t.Error("expected an error for a missing cost CSV")
	}
	badPath := filepath.Join(t.TempDir(), "bad.csv")
	if err := os.WriteFile(badPath, []byte("cluster,cost_usd\ncluster-a,1200\n"), 0o600); err != nil {
		t.Fatalf("write bad csv: %v", err)
	}
	if _, err := exportToFile(t, dbPath, "--cost-csv="+badPath); err == nil {
		t.Error("expected an error for a cost CSV without a period column")
	}
}
