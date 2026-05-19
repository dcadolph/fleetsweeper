package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInitScaffolds verifies the init command writes the expected files.
func TestInitScaffolds(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "starter")
	buf := &bytes.Buffer{}
	initCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"init", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, want := range []string{"values.yaml", "clusterscan.yaml", "serve-config.yaml", "README.md"} {
		path := filepath.Join(dir, want)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
	body, _ := os.ReadFile(filepath.Join(dir, "values.yaml"))
	if !strings.Contains(string(body), "token:") {
		t.Error("values.yaml missing token placeholder")
	}
}

// TestInitRefusesOverwrite verifies a second invocation without --force
// errors rather than silently clobbering.
func TestInitRefusesOverwrite(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "starter")
	rootCmd.SetArgs([]string{"init", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}
	rootCmd.SetArgs([]string{"init", dir})
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected overwrite error without --force")
	}
}
