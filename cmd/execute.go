package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
)

// Execute runs the root command with a signal-cancellable context.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		code := exitCode(err)
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(code)
	}
}

// exitCode maps known errors to specific exit codes.
func exitCode(err error) int {
	switch {
	case errors.Is(err, ErrNoContexts):
		return CodeNoContexts
	case errors.Is(err, ErrNoClients):
		return CodeConnectionError
	default:
		return CodeGeneralError
	}
}
