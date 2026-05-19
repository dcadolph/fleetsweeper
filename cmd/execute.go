package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/tracing"
)

// Execute runs the root command with a signal-cancellable context. SIGINT and
// SIGTERM both trigger graceful shutdown so containerized deployments behave
// correctly under Kubernetes pod termination. OpenTelemetry tracing is
// initialized here when an OTLP endpoint is configured; it is a no-op
// otherwise.
func Execute() {
	server.SetBuildInfo(buildVersion, buildCommit, buildDate)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	shutdownTracing, err := tracing.Init(ctx, "fleetsweeper", buildVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: tracing init failed: %s\n", err)
		shutdownTracing = func(context.Context) error { return nil }
	}
	defer func() {
		shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
		defer cancelShutdown()
		if err := shutdownTracing(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tracing shutdown: %s\n", err)
		}
	}()

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
