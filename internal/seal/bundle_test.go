package seal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// testScanTime is the fixed scan time every bundle fixture is built with.
var testScanTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// testResults returns a small two-cluster scan.
func testResults() map[string]map[string]scanner.Result {
	return map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
		"cluster-b": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.30.5"}}},
	}
}

// testBundle builds the files of a bundle for testResults, sealed with key when key is set.
func testBundle(t *testing.T, key string) map[string][]byte {
	t.Helper()
	results := testResults()
	rpt := report.Build([]string{"cluster-a", "cluster-b"}, results, report.BuildOptions{Timestamp: testScanTime})
	files, err := BundleFiles(rpt, results, "scan-1", BundleOptions{Sealed: key != ""})
	if err != nil {
		t.Fatalf("bundle files: %v", err)
	}
	if key != "" {
		if _, err := Bundle(files, key); err != nil {
			t.Fatalf("seal: %v", err)
		}
	}
	return files
}

// TestBundleFilesContents verifies the bundle carries every artifact, including the raw scan
// results, and only the optional ones that were asked for.
func TestBundleFilesContents(t *testing.T) {
	t.Parallel()
	results := testResults()
	rpt := report.Build([]string{"cluster-a", "cluster-b"}, results, report.BuildOptions{Timestamp: testScanTime})
	tests := []struct {
		Opts      BundleOptions
		WantCost  bool
		WantNS    string
		WantFiles []string
	}{{ // Test 0: Defaults include the core files and no cost.json.
		WantNS:    DefaultPolicyReportNamespace,
		WantFiles: []string{"METADATA.txt", "report.json", "report.pretty.json", "report.html", "scan_results.json"},
	}, { // Test 1: A cost analysis and a namespace are honored.
		Opts:      BundleOptions{PolicyReportNamespace: "audit", Cost: &cost.Analysis{Currency: "USD"}},
		WantCost:  true,
		WantNS:    "audit",
		WantFiles: []string{"cost.json"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			files, err := BundleFiles(rpt, results, "scan-1", test.Opts)
			if err != nil {
				t.Fatalf("bundle files: %v", err)
			}
			for _, name := range test.WantFiles {
				if _, ok := files[name]; !ok {
					t.Errorf("missing %s", name)
				}
			}
			if _, ok := files["cost.json"]; ok != test.WantCost {
				t.Errorf("cost.json present = %v, want %v", ok, test.WantCost)
			}
			var policyReports int
			for name, data := range files {
				if strings.HasPrefix(name, "policyreports/") {
					policyReports++
					if !strings.Contains(string(data), "namespace: "+test.WantNS) {
						t.Errorf("%s lacks namespace %s", name, test.WantNS)
					}
				}
			}
			if policyReports == 0 {
				t.Error("no policy reports in bundle")
			}
			if !strings.Contains(string(files["scan_results.json"]), "v1.30.5") {
				t.Error("scan_results.json does not carry the raw results")
			}
			if strings.Contains(string(files["METADATA.txt"]), "Exported at") {
				t.Error("METADATA.txt carries an export time")
			}
		})
	}
}

// TestBundleDeterministic verifies the same scan writes byte-identical archives and seals to the
// same signature.
func TestBundleDeterministic(t *testing.T) {
	t.Parallel()
	write := func() ([]byte, string) {
		files := testBundle(t, "k")
		var buf bytes.Buffer
		if err := WriteBundle(&buf, "root", files, testScanTime); err != nil {
			t.Fatalf("write: %v", err)
		}
		return buf.Bytes(), string(files[FileName])
	}
	a, sigA := write()
	b, sigB := write()
	if !bytes.Equal(a, b) {
		t.Error("two writes of the same scan differ")
	}
	if sigA != sigB {
		t.Errorf("signatures differ: %s vs %s", sigA, sigB)
	}
}

// TestManifestRoundTrip verifies a manifest lists every file but itself and its signature, in
// path order, and checks clean against the files it was built from.
func TestManifestRoundTrip(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{"b.txt": []byte("b"), "a/x.yaml": []byte("x"), ManifestFile: []byte("old"),
		FileName: []byte("sig")}
	m := Manifest(files)
	lines := strings.Split(strings.TrimSpace(string(m)), "\n")
	names := make([]string, 0, len(lines))
	for _, l := range lines {
		_, name, _ := strings.Cut(l, "  ")
		names = append(names, name)
	}
	if diff := cmp.Diff([]string{"a/x.yaml", "b.txt"}, names); diff != "" {
		t.Errorf("manifest names mismatch (-want +got):\n%s", diff)
	}
	if err := CheckManifest(m, files); err != nil {
		t.Errorf("check: %v", err)
	}
}

// TestCheckManifest verifies every way the files can disagree with the manifest is caught and
// named.
func TestCheckManifest(t *testing.T) {
	t.Parallel()
	base := map[string][]byte{"METADATA.txt": []byte("meta"), "report.json": []byte("{}")}
	manifest := Manifest(base)
	with := func(edit func(map[string][]byte)) map[string][]byte {
		out := map[string][]byte{}
		for k, v := range base {
			out[k] = v
		}
		edit(out)
		return out
	}
	tests := []struct {
		Manifest []byte
		Files    map[string][]byte
		Want     error
		WantText string
	}{{ // Test 0: Matching files pass.
		Manifest: manifest, Files: base,
	}, { // Test 1: An altered file is named.
		Manifest: manifest, Files: with(func(m map[string][]byte) { m["METADATA.txt"] = []byte("meta!") }),
		Want: ErrContents, WantText: "altered METADATA.txt",
	}, { // Test 2: A missing file is named.
		Manifest: manifest, Files: with(func(m map[string][]byte) { delete(m, "report.json") }),
		Want: ErrContents, WantText: "missing report.json",
	}, { // Test 3: An unlisted file is named.
		Manifest: manifest, Files: with(func(m map[string][]byte) { m["extra.sh"] = []byte("x") }),
		Want: ErrContents, WantText: "unlisted extra.sh",
	}, { // Test 4: A garbled line is malformed.
		Manifest: []byte("not a manifest line\n"), Files: base, Want: ErrManifest,
	}, { // Test 5: A file listed twice is malformed.
		Manifest: append(append([]byte{}, manifest...), manifest...), Files: base, Want: ErrManifest,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			err := CheckManifest(test.Manifest, test.Files)
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if test.WantText != "" && !strings.Contains(err.Error(), test.WantText) {
				t.Errorf("err = %v, want it to name %q", err, test.WantText)
			}
		})
	}
}

// TestVerifyBundle verifies a sealed bundle passes and that a wrong key, an edited file, or a
// missing seal fails with the matching error.
func TestVerifyBundle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Edit func(map[string][]byte)
		Key  string
		Want error
	}{{ // Test 0: An untouched bundle verifies.
		Key: "k",
	}, { // Test 1: A wrong key is a mismatch.
		Key: "other", Want: ErrMismatch,
	}, { // Test 2: An edited METADATA.txt fails the contents check.
		Key: "k", Edit: func(m map[string][]byte) { m["METADATA.txt"] = append(m["METADATA.txt"], 'x') },
		Want: ErrContents,
	}, { // Test 3: An edited MANIFEST fails the signature.
		Key: "k", Edit: func(m map[string][]byte) { m[ManifestFile] = append(m[ManifestFile], '\n') },
		Want: ErrMismatch,
	}, { // Test 4: A bundle without a signature is unsealed.
		Key: "k", Edit: func(m map[string][]byte) { delete(m, FileName) }, Want: ErrUnsealed,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			files := testBundle(t, "k")
			if test.Edit != nil {
				test.Edit(files)
			}
			if err := VerifyBundle(files, test.Key); !errors.Is(err, test.Want) {
				t.Errorf("err = %v, want %v", err, test.Want)
			}
		})
	}
}

// TestReadBundle verifies a written bundle reads back whole and that archives that could hide a
// file from verification are rejected.
func TestReadBundle(t *testing.T) {
	t.Parallel()
	type entry struct {
		Name string
		Type byte
	}
	archive := func(entries ...entry) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, e := range entries {
			hdr := &tar.Header{Name: e.Name, Mode: 0o644, Typeflag: e.Type}
			if e.Type == tar.TypeReg {
				hdr.Size = 1
			}
			if e.Type == tar.TypeSymlink {
				hdr.Linkname = "/etc/passwd"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatalf("header: %v", err)
			}
			if e.Type == tar.TypeReg {
				if _, err := tw.Write([]byte("x")); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
		}
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}
	tests := []struct {
		Archive   []byte
		WantRoot  string
		WantFiles []string
		Want      error
	}{{ // Test 0: Files under one root read back relative to it.
		Archive:  archive(entry{"r/", tar.TypeDir}, entry{"r/a", tar.TypeReg}, entry{"r/d/b", tar.TypeReg}),
		WantRoot: "r", WantFiles: []string{"a", "d/b"},
	}, { // Test 1: Two roots are rejected.
		Archive: archive(entry{"r/a", tar.TypeReg}, entry{"s/b", tar.TypeReg}), Want: ErrBundle,
	}, { // Test 2: A path that climbs out is rejected.
		Archive: archive(entry{"r/../a", tar.TypeReg}), Want: ErrBundle,
	}, { // Test 3: A symlink is rejected.
		Archive: archive(entry{"r/a", tar.TypeSymlink}), Want: ErrBundle,
	}, { // Test 4: A duplicate path is rejected.
		Archive: archive(entry{"r/a", tar.TypeReg}, entry{"r/a", tar.TypeReg}), Want: ErrBundle,
	}, { // Test 5: A file at the top level is rejected.
		Archive: archive(entry{"a", tar.TypeReg}), Want: ErrBundle,
	}, { // Test 6: Bytes that are not gzip are rejected.
		Archive: []byte("plain"), Want: ErrBundle,
	}, { // Test 7: An empty archive is rejected.
		Archive: archive(), Want: ErrBundle,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			root, files, err := ReadBundle(bytes.NewReader(test.Archive))
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if err != nil {
				return
			}
			var names []string
			for name := range files {
				names = append(names, name)
			}
			if diff := cmp.Diff(test.WantFiles, names, cmpSorted); diff != "" {
				t.Errorf("files mismatch (-want +got):\n%s", diff)
			}
			if root != test.WantRoot {
				t.Errorf("root = %q, want %q", root, test.WantRoot)
			}
		})
	}
}

// TestWriteReadBundleRoundTrip verifies a sealed bundle written to an archive reads back and
// verifies.
func TestWriteReadBundleRoundTrip(t *testing.T) {
	t.Parallel()
	files := testBundle(t, "k")
	var buf bytes.Buffer
	if err := WriteBundle(&buf, "fleetsweeper-export-scan-1", files, testScanTime); err != nil {
		t.Fatalf("write: %v", err)
	}
	root, got, err := ReadBundle(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if root != "fleetsweeper-export-scan-1" {
		t.Errorf("root = %q", root)
	}
	if diff := cmp.Diff(files, got); diff != "" {
		t.Errorf("files mismatch (-want +got):\n%s", diff)
	}
	if err := VerifyBundle(got, "k"); err != nil {
		t.Errorf("verify: %v", err)
	}
}

// cmpSorted compares string slices without regard to order.
var cmpSorted = cmpopts.SortSlices(func(a, b string) bool { return a < b }) //nolint:gochecknoglobals // Not modified, simplifies testing.
