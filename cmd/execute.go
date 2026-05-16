package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Execute runs the root command with a signal-cancellable context. SIGINT and
// SIGTERM both trigger graceful shutdown so containerized deployments behave
// correctly under Kubernetes pod termination.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	case errors.Is(err, ErrNoDatabase):
		return CodeNoDB
	default:
		return CodeGeneralError
	}
}
