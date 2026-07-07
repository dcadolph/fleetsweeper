package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/explain"
)

// execWhy runs the why subcommand and captures its output.
func execWhy(t *testing.T, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(append([]string{"why"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestWhyList verifies the topic index renders.
func TestWhyList(t *testing.T) {
	out, err := execWhy(t, "list", "--no-color=true")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "Available topics") {
		t.Errorf("list output missing header:\n%s", out)
	}
}

// TestWhyKnownTopic verifies a real topic renders its explanation.
func TestWhyKnownTopic(t *testing.T) {
	keys := explain.Keys()
	if len(keys) == 0 {
		t.Skip("no explain topics registered")
	}
	out, err := execWhy(t, keys[0], "--no-color=true")
	if err != nil {
		t.Fatalf("topic %q: %v", keys[0], err)
	}
	if strings.TrimSpace(out) == "" {
		t.Errorf("topic %q rendered nothing", keys[0])
	}
}

// TestWhyUnknownTopic verifies an unmatched topic is a non-nil error.
func TestWhyUnknownTopic(t *testing.T) {
	if _, err := execWhy(t, "definitely-not-a-real-topic", "--no-color=true"); err == nil {
		t.Error("expected error for unknown topic")
	}
}
