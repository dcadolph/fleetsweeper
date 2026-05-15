package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/logutil"
	"github.com/dcadolph/fleetsweeper/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web UI and API server",
	Long:  "Launch a web server with an API and dashboard for browsing scan results, groups, trends, and outliers.",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().String("addr", ":8080", "Listen address.")
	serveCmd.Flags().Duration("scan-interval", 0, "Auto-scan interval (e.g. 30m, 1h). 0 disables.")
	serveCmd.Flags().StringSlice("contexts", nil, "Kubeconfig contexts for scheduled scans.")
	serveCmd.Flags().Bool("all-contexts", false, "Use all kubeconfig contexts for scheduled scans.")
	serveCmd.Flags().Int("workers", 5, "Maximum concurrent operations for scans.")
}

// runServe starts the HTTP server.
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
	scanInterval, _ := cmd.Flags().GetDuration("scan-interval")
	workers, _ := cmd.Flags().GetInt("workers")
	allContexts, _ := cmd.Flags().GetBool("all-contexts")
	contextNames, _ := cmd.Flags().GetStringSlice("contexts")

	registry := buildRegistry()

	srv := server.New(server.Config{
		Store:          s,
		Registry:       registry,
		Log:            log,
		KubeconfigPath: kubeconfigPath,
		Workers:        workers,
	})

	// Start scheduled scanning if configured.
	if scanInterval > 0 {
		contexts, err := resolveScheduleContexts(kubeconfigPath, contextNames, allContexts)
		if err != nil {
			return fmt.Errorf("resolve schedule contexts: %w", err)
		}
		go srv.StartScheduler(ctx, scanInterval, contexts)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "fleetsweeper server listening on %s\n", addr)
	return srv.ListenAndServe(addr)
}

// resolveScheduleContexts determines which contexts to use for scheduled scans.
func resolveScheduleContexts(kubeconfigPath string, explicit []string, all bool) ([]string, error) {
	if all {
		return kube.AvailableContexts(kubeconfigPath)
	}
	return explicit, nil
}