package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestArchitecturePackageTable checks that the package table in docs/architecture.md lists
// every package in the module and nothing else.
func TestArchitecturePackageTable(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile(filepath.Join("docs", "architecture.md"))
	if err != nil {
		t.Fatalf("read architecture doc: %v", err)
	}
	row := regexp.MustCompile("^\\| `([^`]+)` +\\|")
	var documented []string
	for _, line := range strings.Split(string(doc), "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			documented = append(documented, m[1])
		}
	}
	sort.Strings(documented)
	if diff := cmp.Diff(modulePackages(t, "."), documented); diff != "" {
		t.Errorf("package table mismatch (-want +got):\n%s", diff)
	}
}

// modulePackages returns the slash-separated path, relative to root, of every directory below
// root that holds a non-test Go file. It skips testdata and hidden directories.
func modulePackages(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		if dir != "." {
			seen[filepath.ToSlash(dir)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	pkgs := make([]string, 0, len(seen))
	for p := range seen {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	return pkgs
}
