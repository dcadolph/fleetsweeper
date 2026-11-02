package util

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestDefaultStatePath verifies XDG_STATE_HOME wins when absolute, the home directory is the
// fallback, and a process with neither has no default.
func TestDefaultStatePath(t *testing.T) {
	tests := []struct {
		XDG        string
		Home       string
		WantResult string
		Want       error
	}{{ // Test 0: An absolute XDG_STATE_HOME wins.
		XDG: "/xdg", Home: "/home/u", WantResult: filepath.Join("/xdg", "fleetsweeper", "fleet.db"),
	}, { // Test 1: No XDG_STATE_HOME falls back to the home directory.
		Home: "/home/u", WantResult: filepath.Join("/home/u", ".local", "state", "fleetsweeper", "fleet.db"),
	}, { // Test 2: A relative XDG_STATE_HOME is ignored, as the XDG spec requires.
		XDG: "rel", Home: "/home/u", WantResult: filepath.Join("/home/u", ".local", "state", "fleetsweeper", "fleet.db"),
	}, { // Test 3: Neither set has no default.
		Want: ErrStatePath,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", test.XDG)
			t.Setenv("HOME", test.Home)
			got, err := DefaultStatePath()
			if !errors.Is(err, test.Want) {
				t.Fatalf("error: got %v, want %v", err, test.Want)
			}
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
