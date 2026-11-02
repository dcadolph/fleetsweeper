package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ErrStatePath indicates no default state directory can be derived for this user.
var ErrStatePath = errors.New("no default state directory")

// DefaultStatePath returns the file fleetsweeper keeps its scan store in when none is named:
// $XDG_STATE_HOME/fleetsweeper/fleet.db when XDG_STATE_HOME is absolute, else
// ~/.local/state/fleetsweeper/fleet.db, and the user config directory on Windows.
func DefaultStatePath() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "fleetsweeper", "fleet.db"), nil
	}
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrStatePath, err)
		}
		return filepath.Join(dir, "fleetsweeper", "fleet.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrStatePath, err)
	}
	return filepath.Join(home, ".local", "state", "fleetsweeper", "fleet.db"), nil
}
