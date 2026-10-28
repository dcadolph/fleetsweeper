package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// verifyKey is the seal key the verify tests sign with.
const verifyKey = "test-secret"

// sealedFiles returns the files of a bundle for the export fixture scan, sealed with
// verifyKey.
func sealedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	rpt := report.Build([]string{"cluster-a", "cluster-b", "cluster-c"}, exportScanResults(),
		report.BuildOptions{Timestamp: exportScanTime})
	files, err := seal.BundleFiles(rpt, exportScanResults(), "scan-verify", seal.BundleOptions{Sealed: true})
	if err != nil {
		t.Fatalf("bundle files: %v", err)
	}
	if _, err := seal.Bundle(files, verifyKey); err != nil {
		t.Fatalf("seal bundle: %v", err)
	}
	return files
}

// writeBundleFile writes files as a bundle in a temp dir and returns its path.
func writeBundleFile(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := seal.WriteBundle(&buf, "fleetsweeper-export-scan-verify", files, exportScanTime); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
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

// TestVerify drives verify over a valid bundle and every way one can be wrong.
func TestVerify(t *testing.T) {
	tests := []struct {
		Mutate     func(files map[string][]byte)
		Key        string
		WantOutput string
		Want       error
	}{{ // Test 0: An untouched bundle verifies.
		Key: verifyKey, WantOutput: "ok: signature matches MANIFEST and all",
	}, { // Test 1: Editing METADATA.txt fails on contents.
		Mutate: func(files map[string][]byte) {
			files["METADATA.txt"] = append(files["METADATA.txt"], "edited\n"...)
		},
		Key: verifyKey, WantOutput: "altered METADATA.txt", Want: seal.ErrContents,
	}, { // Test 2: Editing scan_results.json fails on contents.
		Mutate: func(files map[string][]byte) {
			files["scan_results.json"] = bytes.ReplaceAll(files["scan_results.json"], []byte("v1.30.5"), []byte("v1.31.2"))
		},
		Key: verifyKey, WantOutput: "altered scan_results.json", Want: seal.ErrContents,
	}, { // Test 3: A file the manifest does not list fails.
		Mutate: func(files map[string][]byte) {
			files["extra.txt"] = []byte("smuggled")
		},
		Key: verifyKey, WantOutput: "unlisted extra.txt", Want: seal.ErrContents,
	}, { // Test 4: Removing a listed file fails.
		Mutate: func(files map[string][]byte) {
			delete(files, "report.html")
		},
		Key: verifyKey, WantOutput: "missing report.html", Want: seal.ErrContents,
	}, { // Test 5: Rewriting the manifest to match an edit breaks the signature.
		Mutate: func(files map[string][]byte) {
			files["report.json"] = append(files["report.json"], ' ')
			files[seal.ManifestFile] = seal.Manifest(files)
		},
		Key: verifyKey, WantOutput: "signature mismatch", Want: seal.ErrMismatch,
	}, { // Test 6: The wrong key fails.
		Key: "other-secret", WantOutput: "signature mismatch", Want: seal.ErrMismatch,
	}, { // Test 7: A bundle without a manifest is unsealed.
		Mutate: func(files map[string][]byte) {
			delete(files, seal.ManifestFile)
			delete(files, seal.FileName)
		},
		Key: verifyKey, WantOutput: "export with --seal-key", Want: seal.ErrUnsealed,
	}, { // Test 8: A signature that is not sha256=<hex> is malformed.
		Mutate: func(files map[string][]byte) {
			files[seal.FileName] = []byte("md5=abc\n")
		},
		Key: verifyKey, WantOutput: "malformed", Want: seal.ErrMalformed,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			files := sealedFiles(t)
			if test.Mutate != nil {
				test.Mutate(files)
			}
			out, err := execVerify(t, writeBundleFile(t, files), "--seal-key="+test.Key)
			if test.Want == nil && err != nil {
				t.Fatalf("verify: %v\n%s", err, out)
			}
			if !errors.Is(err, test.Want) {
				t.Errorf("error: want %v, got %v", test.Want, err)
			}
			if !strings.Contains(out, test.WantOutput) {
				t.Errorf("output does not contain %q:\n%s", test.WantOutput, out)
			}
		})
	}
}

// TestVerifyMissingKey verifies the required-key guard.
func TestVerifyMissingKey(t *testing.T) {
	bundle := writeBundleFile(t, sealedFiles(t))
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

// TestVerifyNotABundle verifies that a file that is not a gzipped tar is a bundle error.
func TestVerifyNotABundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.tar.gz")
	if err := os.WriteFile(path, []byte("not a bundle"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := execVerify(t, path, "--seal-key=k"); !errors.Is(err, seal.ErrBundle) {
		t.Errorf("want ErrBundle, got %v", err)
	}
}
