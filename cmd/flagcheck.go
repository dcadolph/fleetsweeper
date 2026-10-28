package cmd

import (
	"fmt"
	"strings"
)

// oneOf returns an ErrFlagValue error naming flag, value, and allowed when value is not one of
// allowed.
func oneOf(flag, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("%w: --%s %q: want one of %s", ErrFlagValue, flag, value,
		strings.Join(allowed, ", "))
}
