package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestApplyConfigFile verifies a YAML file is parsed and applied to flags.
func TestApplyConfigFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
addr: ":9090"
auth-token: "test-token"
cors-origin: ["https://a.example.com", "https://b.example.com"]
controller: true
workers: 8
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("addr", ":8080", "")
	cmd.Flags().String("auth-token", "", "")
	cmd.Flags().StringSlice("cors-origin", nil, "")
	cmd.Flags().Bool("controller", false, "")
	cmd.Flags().Int("workers", 5, "")
	cmd.Flags().String("config", path, "")

	if err := applyConfigFile(cmd); err != nil {
		t.Fatalf("apply: %v", err)
	}
	addr, _ := cmd.Flags().GetString("addr")
	if addr != ":9090" {
		t.Errorf("addr: want :9090, got %s", addr)
	}
	token, _ := cmd.Flags().GetString("auth-token")
	if token != "test-token" {
		t.Errorf("token: want test-token, got %s", token)
	}
	origins, _ := cmd.Flags().GetStringSlice("cors-origin")
	if len(origins) != 2 || origins[0] != "https://a.example.com" {
		t.Errorf("cors-origin: %v", origins)
	}
	controller, _ := cmd.Flags().GetBool("controller")
	if !controller {
		t.Error("controller flag not applied")
	}
	workers, _ := cmd.Flags().GetInt("workers")
	if workers != 8 {
		t.Errorf("workers: want 8, got %d", workers)
	}
}

// TestApplyConfigFileSkipsExplicit verifies CLI-supplied flags are not
// overwritten by config file values.
func TestApplyConfigFileSkipsExplicit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("addr: \":7777\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("addr", ":8080", "")
	cmd.Flags().String("config", path, "")
	if err := cmd.Flags().Set("addr", ":4242"); err != nil {
		t.Fatalf("set explicit: %v", err)
	}

	if err := applyConfigFile(cmd); err != nil {
		t.Fatalf("apply: %v", err)
	}
	addr, _ := cmd.Flags().GetString("addr")
	if addr != ":4242" {
		t.Errorf("expected explicit value to win, got %s", addr)
	}
}

// TestApplyConfigFileRejectsUnknownFlag verifies an unrecognized key is an
// error rather than silently ignored.
func TestApplyConfigFileRejectsUnknownFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("nope: 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := &cobra.Command{}
	cmd.Flags().String("config", path, "")
	if err := applyConfigFile(cmd); err == nil {
		t.Error("expected error for unknown flag")
	}
}
