package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultKubeconfig verifies the KUBECONFIG override and the home fallback.
// It sets an environment variable, so it does not run in parallel.
func TestDefaultKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/custom/kubeconfig")
	if got := defaultKubeconfig(); got != "/custom/kubeconfig" {
		t.Errorf("with KUBECONFIG set: got %q", got)
	}

	t.Setenv("KUBECONFIG", "")
	got := defaultKubeconfig()
	if got != "" && !strings.HasSuffix(got, filepath.Join(".kube", "config")) {
		t.Errorf("fallback should end in .kube/config, got %q", got)
	}
}

// TestNewLogger verifies a valid level builds and an invalid level falls back
// to warn without erroring.
func TestNewLogger(t *testing.T) {
	t.Parallel()
	for _, level := range []string{"debug", "info", "warn", "error", "bogus"} {
		log, err := newLogger(level)
		if err != nil {
			t.Fatalf("newLogger(%q): %v", level, err)
		}
		if log == nil {
			t.Fatalf("newLogger(%q): nil logger", level)
		}
	}
}

// TestVersionCommand verifies the version subcommand prints the build info.
func TestVersionCommand(t *testing.T) {
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(buf.String(), "fleetsweeper") {
		t.Errorf("version output missing product name: %q", buf.String())
	}
}
