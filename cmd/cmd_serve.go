package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/logutil"
	"github.com/dcadolph/fleetsweeper/internal/server"
)

// serveCmd starts the HTTP API and web UI.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web UI and API server",
	Long:  "Launch a web server with an API and dashboard for browsing scan results, groups, trends, and outliers.",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().String("addr", ":8080", "Listen address for the public API and UI.")
	serveCmd.Flags().String("admin-addr", "", "Optional listen address for pprof and metrics (empty disables).")
	serveCmd.Flags().Duration("scan-interval", 0, "Auto-scan interval (for example 30m, 1h). 0 disables.")
	serveCmd.Flags().StringSlice("contexts", nil, "Kubeconfig contexts for scheduled scans.")
	serveCmd.Flags().Bool("all-contexts", false, "Use all kubeconfig contexts for scheduled scans.")
	serveCmd.Flags().Int("workers", 5, "Maximum concurrent operations for scans.")
	serveCmd.Flags().String("auth-token", "", "Bearer token required for mutating endpoints (POST, DELETE).")
	serveCmd.Flags().Bool("insecure", false, "Disable authentication entirely. Required if --auth-token is empty and you accept the risk.")
	serveCmd.Flags().StringSlice("cors-origin", nil, "Allowed CORS origins. Repeat for multiple. Empty means cross-origin requests are refused.")
	serveCmd.Flags().Bool("demo", false, "Serve a synthetic fleet on /globe when no scans exist. Useful for previewing the UI without any real clusters.")
	serveCmd.MarkFlagsMutuallyExclusive("all-contexts", "contexts")
}

// runServe starts the HTTP server and blocks until the parent context is cancelled.
func runServe(cmd *cobra.Command, _ []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	ctx := cmd.Context()
	log := logutil.UnwrapLogger(ctx)
	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	addr, _ := cmd.Flags().GetString("addr")
	adminAddr, _ := cmd.Flags().GetString("admin-addr")
	scanInterval, _ := cmd.Flags().GetDuration("scan-interval")
	workers, _ := cmd.Flags().GetInt("workers")
	allContexts, _ := cmd.Flags().GetBool("all-contexts")
	contextNames, _ := cmd.Flags().GetStringSlice("contexts")
	authToken, _ := cmd.Flags().GetString("auth-token")
	insecure, _ := cmd.Flags().GetBool("insecure")
	corsOrigins, _ := cmd.Flags().GetStringSlice("cors-origin")
	demo, _ := cmd.Flags().GetBool("demo")

	if authToken == "" && !insecure {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: --auth-token not set; mutating endpoints will return 403. Pass --insecure to allow without a token.")
	}

	registry := buildRegistry()

	srv := server.New(server.Config{
		Store:          s,
		Registry:       registry,
		Log:            log,
		KubeconfigPath: kubeconfigPath,
		Workers:        workers,
		AuthToken:      authToken,
		Insecure:       insecure,
		CORSOrigins:    corsOrigins,
		Demo:           demo,
	})

	if scanInterval > 0 {
		contexts, err := resolveScheduleContexts(kubeconfigPath, contextNames, allContexts)
		if err != nil {
			return fmt.Errorf("resolve schedule contexts: %w", err)
		}
		go srv.StartScheduler(ctx, scanInterval, contexts)
	}

	if adminAddr != "" {
		go func() {
			if err := srv.ListenAndServeAdmin(adminAddr); err != nil {
				log.Warn("admin server stopped", logutil.ErrorField(err))
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "fleetsweeper server listening on %s\n", addr)
		errCh <- srv.ListenAndServe(addr)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		fmt.Fprintln(cmd.ErrOrStderr(), "shutdown signal received; draining...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// resolveScheduleContexts determines which contexts to use for scheduled scans.
func resolveScheduleContexts(kubeconfigPath string, explicit []string, all bool) ([]string, error) {
	if all {
		return kube.AvailableContexts(kubeconfigPath)
	}
	return explicit, nil
}
