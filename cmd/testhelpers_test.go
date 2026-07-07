package cmd

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// newBufferedCmd returns a bare cobra command whose stdout and stderr are
// wired to buf. Handy for exercising output helpers that take a *cobra.Command
// without going through the shared rootCmd.
func newBufferedCmd(buf *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

// newStoreCmd returns a standalone cobra command carrying the store-related
// flags (db, db-driver, pretty) preset to dbPath. Tests use it to call run
// functions directly, sidestepping the shared rootCmd whose StringSlice flags
// accumulate values across Execute calls.
func newStoreCmd(dbPath string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("db", dbPath, "")
	cmd.Flags().String("db-driver", "", "")
	cmd.Flags().Bool("pretty", false, "")
	// Run functions read cmd.Context(); cobra returns nil when it was never
	// set, which passing to database/sql would hang. Anchor a real context.
	cmd.SetContext(context.Background())
	return cmd
}

// rootCmdMu serializes access to the package-global rootCmd across
// tests. Cobra holds args, output writers, and lazily-attached
// completion subcommands directly on the Command, so two parallel
// tests that call rootCmd.SetArgs + rootCmd.Execute race even when
// they otherwise touch disjoint stores.
var rootCmdMu sync.Mutex

// lockRootCmd locks the shared rootCmd mutex and returns the
// release callback. Tests defer the return value so the lock is
// scoped to a single rootCmd interaction, not the whole test. That
// matters for helpers that call rootCmd.Execute repeatedly within
// one test (each call needs to re-acquire the lock).
//
// Usage:
//
//	func TestThing(t *testing.T) {
//	    defer lockRootCmd(t)()
//	    rootCmd.SetArgs(...)
//	    rootCmd.Execute()
//	}
func lockRootCmd(t *testing.T) func() {
	t.Helper()
	rootCmdMu.Lock()
	return rootCmdMu.Unlock
}
