package cmd

import (
	"sync"
	"testing"
)

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
