package cmd

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points the default store at a temporary state directory, so a command run without
// --db never writes into the real home directory. No test may create the default store in that
// shared directory: the doctor checks read its absence as "no store yet". A test that needs a
// default store sets XDG_STATE_HOME to its own temporary directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fleetsweeper-cmd-state-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "state dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_STATE_HOME", dir); err != nil {
		fmt.Fprintf(os.Stderr, "set XDG_STATE_HOME: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
