package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// fixtureReport builds a minimal *report.Report. Only the fields the
// bundle writer touches are populated; everything else stays at its
// zero value, which is fine for the export path.
func fixtureReport(t *testing.T) *report.Report {
	t.Helper()
	results := map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
		"cluster-b": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.5"}}},
	}
	return report.Build([]string{"cluster-a", "cluster-b"}, results)
}

// readBundleEntries extracts named entries from a tar.gz produced by
// writeBundle, returning a map of base filename to bytes.
func readBundleEntries(t *testing.T, raw []byte, names ...string) map[string][]byte {
	t.Helper()
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		base := filepath.Base(hdr.Name)
		if !wanted[base] {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", base, err)
		}
		out[base] = data
	}
	return out
}

func TestWriteBundle_NoSealKeyOmitsSignature(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeBundle(&buf, context.Background(), fixtureReport(t),
		"scan-1", "", "fleetsweeper", ""); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	entries := readBundleEntries(t, buf.Bytes(), seal.SourceFile, seal.FileName)
	if _, ok := entries[seal.SourceFile]; !ok {
		t.Errorf("expected %s in bundle", seal.SourceFile)
	}
	if _, ok := entries[seal.FileName]; ok {
		t.Errorf("expected no %s when seal-key empty", seal.FileName)
	}
}

func TestWriteBundle_SealedRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeBundle(&buf, context.Background(), fixtureReport(t),
		"scan-2", "", "fleetsweeper", "topsecret"); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	reportBytes, signature, err := readSealedBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("read sealed bundle: %v", err)
	}
	if signature == "" {
		t.Fatal("expected signature in bundle")
	}
	if err := seal.Verify(reportBytes, signature, "topsecret"); err != nil {
		t.Errorf("verify good key: %v", err)
	}
	if err := seal.Verify(reportBytes, signature, "wrong"); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("verify wrong key: want ErrMismatch, got %v", err)
	}

	tampered := append([]byte{}, reportBytes...)
	tampered[len(tampered)-2] ^= 0x01
	if err := seal.Verify(tampered, signature, "topsecret"); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("verify tampered report: want ErrMismatch, got %v", err)
	}
}

func TestReadSealedBundle_MissingReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeTarFile(tw, "root/METADATA.txt", []byte("hi")); err != nil {
		t.Fatalf("write tar: %v", err)
	}
	tw.Close()
	gz.Close()

	if _, _, err := readSealedBundle(bytes.NewReader(buf.Bytes())); err == nil ||
		!strings.Contains(err.Error(), "missing") {
		t.Errorf("want missing-report error, got %v", err)
	}
}

func TestReadSealedBundle_FromDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")

	var buf bytes.Buffer
	if err := writeBundle(&buf, context.Background(), fixtureReport(t),
		"scan-3", "", "fleetsweeper", "k"); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	body, sig, err := readSealedBundle(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := seal.Verify(body, sig, "k"); err != nil {
		t.Errorf("on-disk verify: %v", err)
	}
}
