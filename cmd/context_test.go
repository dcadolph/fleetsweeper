package cmd

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
)

// TestCmdContext verifies cmdContext never returns a nil context and passes an
// existing context through unchanged.
func TestCmdContext(t *testing.T) {
	t.Parallel()

	// Test 0: A command that never ran through Execute has a nil context;
	// cmdContext substitutes a usable background context.
	if got := cmdContext(&cobra.Command{}); got == nil {
		t.Fatal("cmdContext returned nil for a command with no context")
	}

	// Test 1: When a context is set, cmdContext returns it unchanged.
	type ctxKey struct{}
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), ctxKey{}, "v"))
	if got := cmdContext(cmd).Value(ctxKey{}); got != "v" {
		t.Errorf("cmdContext did not return the command's own context, value = %v", got)
	}
}
