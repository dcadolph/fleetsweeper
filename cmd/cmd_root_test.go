package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// TestNewLogger verifies valid levels build and unknown levels return ErrLogLevel.
func TestNewLogger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Want  error
		Level string
	}{
		{Level: "debug"},                      // Test 0: Debug builds.
		{Level: "info"},                       // Test 1: Info builds.
		{Level: "warn"},                       // Test 2: Warn builds.
		{Level: "error"},                      // Test 3: Error builds.
		{Level: "verbose", Want: ErrLogLevel}, // Test 4: Unknown level is rejected.
		{Level: "loud", Want: ErrLogLevel},    // Test 5: Another unknown level is rejected.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			log, err := newLogger(test.Level)
			if !errors.Is(err, test.Want) {
				t.Fatalf("newLogger(%q) error = %v, want %v", test.Level, err, test.Want)
			}
			if test.Want == nil && log == nil {
				t.Fatalf("newLogger(%q): nil logger", test.Level)
			}
		})
	}
}

// TestLoggerTimestamp verifies log lines carry an ISO 8601 timestamp.
func TestLoggerTimestamp(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "log.txt")
	cfg, err := loggerConfig("info")
	if err != nil {
		t.Fatalf("loggerConfig: %v", err)
	}
	cfg.OutputPaths = []string{path}
	cfg.ErrorOutputPaths = []string{path}
	log, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	log.Info("hello")
	_ = log.Sync()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`).Match(data) {
		t.Errorf("timestamp not ISO 8601: %q", data)
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
