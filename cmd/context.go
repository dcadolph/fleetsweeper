package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// cmdContext returns the command's context, or a background context when the
// command carries none. Cobra leaves the context nil until a command runs
// through Execute, and a nil context passed to a database/sql ...Context method
// blocks forever, so every call site sources its context here.
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
