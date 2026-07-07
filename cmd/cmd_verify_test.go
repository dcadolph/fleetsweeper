package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// writeSealedBundle writes a gzipped tar containing report.json and, when
// sig is non-empty, report.sig. Returns the bundle path.
func writeSealedBundle(t *testing.T, reportBytes []byte, sig string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	writeEntry := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	writeEntry(seal.SourceFile, reportBytes)
	if sig != "" {
		writeEntry(seal.FileName, []byte(sig))
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return path
}

// execVerify runs the verify subcommand and captures its output.
func execVerify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(append([]string{"verify"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestVerifyValidSeal verifies a correctly-signed bundle passes.
func TestVerifyValidSeal(t *testing.T) {
	const key = "test-secret"
	reportBytes := []byte(`{"fleet":"ok"}`)
	sig, err := seal.Sign(reportBytes, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	bundle := writeSealedBundle(t, reportBytes, sig)

	out, err := execVerify(t, bundle, "--seal-key="+key)
	if err != nil {
		t.Fatalf("verify valid: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ok: signature matches") {
		t.Errorf("expected ok message, got:\n%s", out)
	}
}

// TestVerifyTampered verifies a mismatched signature is rejected.
func TestVerifyTampered(t *testing.T) {
	const key = "test-secret"
	sig, _ := seal.Sign([]byte("original"), key)
	// Sign covers "original" but the bundle ships different bytes.
	bundle := writeSealedBundle(t, []byte("tampered"), sig)
	if _, err := execVerify(t, bundle, "--seal-key="+key); err == nil {
		t.Error("expected mismatch error for tampered bundle")
	}
}

// TestVerifyMissingKey verifies the required-key guard.
func TestVerifyMissingKey(t *testing.T) {
	bundle := writeSealedBundle(t, []byte("x"), "")
	t.Setenv("FLEETSWEEPER_SEAL_KEY", "")
	if _, err := execVerify(t, bundle, "--seal-key="); err == nil {
		t.Error("expected error when no seal key is provided")
	}
}

// TestVerifyMissingFile verifies a nonexistent bundle path errors.
func TestVerifyMissingFile(t *testing.T) {
	if _, err := execVerify(t, filepath.Join(t.TempDir(), "absent.tar.gz"), "--seal-key=k"); err == nil {
		t.Error("expected error for missing bundle file")
	}
}
