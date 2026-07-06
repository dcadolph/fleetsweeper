package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/leader"
	"github.com/dcadolph/fleetsweeper/internal/logutil"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
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
	serveCmd.Flags().String("slack-webhook-url", "", "Slack incoming-webhook URL. When set, new critical findings are posted to this channel after each scan.")
	serveCmd.Flags().String("fleetdrift-output", "", "Local directory to write FleetDriftReport YAMLs after every scan. One file per cluster. Empty disables.")
	serveCmd.Flags().String("policy-report-output", "", "Local directory to write wgpolicyk8s.io PolicyReport YAMLs after every scan. Empty disables.")
	serveCmd.Flags().String("policy-report-namespace", "fleetsweeper", "Namespace placed on emitted PolicyReports.")
	serveCmd.Flags().String("cost-csv", "", "Path to a CSV mapping clusters to monthly costs. See deploy/examples/cost.csv. Empty disables cost correlation.")
	serveCmd.Flags().String("webhook-config", "", "Path to a YAML file of outbound webhook subscribers. See deploy/examples/webhooks.yaml.")
	serveCmd.Flags().String("webhook-secret", "", "HMAC-SHA256 shared secret for the inbound /webhooks/scan-trigger endpoint. Empty disables inbound webhooks.")
	serveCmd.Flags().String("seal-key", "", "HMAC-SHA256 key used to sign saved scan reports. Empty disables sealing.")
	serveCmd.Flags().Bool("controller", false, "Enable the ClusterScan controller: watch ClusterScan CRs in the home cluster and reconcile them by triggering scans on their declared interval.")
	serveCmd.Flags().String("controller-namespace", "", "Namespace the controller watches. Empty watches all namespaces (requires cluster-wide RBAC).")
	serveCmd.Flags().String("controller-context", "", "Kubeconfig context the controller uses to reach the home cluster. Empty uses the default context or in-cluster config.")
	serveCmd.Flags().Duration("controller-poll", 15*time.Second, "How often the controller re-evaluates ClusterScan resources.")
	serveCmd.Flags().Bool("leader-election", true, "Enable leader election for the scheduler and controller. Honored only when running inside Kubernetes. Multiple replicas without leader election will double-fire scheduled work.")
	serveCmd.Flags().String("leader-namespace", "", "Namespace for the leader-election Lease object. Defaults to $POD_NAMESPACE.")
	serveCmd.Flags().String("leader-name", "fleetsweeper", "Name of the leader-election Lease object.")
	serveCmd.Flags().String("config", "", "Path to a YAML config file. File values are applied as flag defaults; CLI flags override.")
	serveCmd.Flags().Duration("audit-retention", 0, "Delete audit_log rows older than this duration on an hourly ticker. 0 disables retention (table grows unbounded).")
	serveCmd.Flags().String("admission-addr", "", "Listen address for the fleet-norm admission webhook (e.g. :8443). Empty disables the webhook.")
	serveCmd.Flags().String("admission-cert", "", "Path to a PEM TLS certificate for the admission webhook. Empty generates a self-signed cert at startup.")
	serveCmd.Flags().String("admission-key", "", "Path to the matching PEM private key.")
	serveCmd.Flags().StringSlice("admission-dns", []string{"fleetsweeper.fleetsweeper.svc"}, "Additional DNS SANs to include on the generated certificate.")
	serveCmd.Flags().String("admission-mode", "advisory", "advisory: warn only; enforce: deny pods that deviate from the fleet norm.")
	serveCmd.MarkFlagsMutuallyExclusive("all-contexts", "contexts")
}

// runServe starts the HTTP server and blocks until the parent context is canceled.
func runServe(cmd *cobra.Command, _ []string) error {
	if err := applyConfigFile(cmd); err != nil {
		return err
	}
	demo, _ := cmd.Flags().GetBool("demo")
	s, err := openServeStore(cmd, demo)
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
	slackWebhookURL, _ := cmd.Flags().GetString("slack-webhook-url")
	fleetDriftOutput, _ := cmd.Flags().GetString("fleetdrift-output")
	policyReportOutput, _ := cmd.Flags().GetString("policy-report-output")
	policyReportNS, _ := cmd.Flags().GetString("policy-report-namespace")
	costCSV, _ := cmd.Flags().GetString("cost-csv")
	webhookConfig, _ := cmd.Flags().GetString("webhook-config")
	webhookSecret, _ := cmd.Flags().GetString("webhook-secret")
	sealKey, _ := cmd.Flags().GetString("seal-key")

	if authToken == "" && !insecure {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: --auth-token not set; mutating endpoints will return 403. Pass --insecure to allow without a token.")
	}

	registry := buildRegistry()

	oidcIssuer, _ := cmd.Flags().GetString("oidc-issuer-url")
	oidcClient, _ := cmd.Flags().GetString("oidc-client-id")
	oidcSecret, _ := cmd.Flags().GetString("oidc-client-secret")
	oidcRedirect, _ := cmd.Flags().GetString("oidc-redirect-url")
	oidcScopes, _ := cmd.Flags().GetStringSlice("oidc-scopes")
	sessionSecret, _ := cmd.Flags().GetString("session-secret")
	sessionLifetime, _ := cmd.Flags().GetDuration("session-lifetime")
	oidcAdminClaim, _ := cmd.Flags().GetString("oidc-admin-claim")
	oidcOpClaim, _ := cmd.Flags().GetString("oidc-operator-claim")
	oidcDefaultRole, _ := cmd.Flags().GetString("oidc-default-role")
	readRPM, _ := cmd.Flags().GetInt("rate-limit-read-rpm")
	writeRPM, _ := cmd.Flags().GetInt("rate-limit-write-rpm")

	srv := server.New(server.Config{
		Store:                 s,
		Registry:              registry,
		Log:                   log,
		KubeconfigPath:        kubeconfigPath,
		Workers:               workers,
		AuthToken:             authToken,
		Insecure:              insecure,
		CORSOrigins:           corsOrigins,
		Demo:                  demo,
		SlackWebhookURL:       slackWebhookURL,
		FleetDriftOutputDir:   fleetDriftOutput,
		PolicyReportOutputDir: policyReportOutput,
		PolicyReportNamespace: policyReportNS,
		CostCSVPath:           costCSV,
		WebhookConfigPath:     webhookConfig,
		WebhookSecret:         webhookSecret,
		SealKey:               sealKey,
		ReadRPM:               readRPM,
		WriteRPM:              writeRPM,
		OIDC: server.OIDCConfig{
			IssuerURL:       oidcIssuer,
			ClientID:        oidcClient,
			ClientSecret:    oidcSecret,
			RedirectURL:     oidcRedirect,
			Scopes:          oidcScopes,
			SessionSecret:   sessionSecret,
			SessionLifetime: sessionLifetime,
			AdminClaim:      oidcAdminClaim,
			OperatorClaim:   oidcOpClaim,
			DefaultRole:     oidcDefaultRole,
		},
	})

	leaderEnabled, _ := cmd.Flags().GetBool("leader-election")
	leaderNamespace, _ := cmd.Flags().GetString("leader-namespace")
	leaderName, _ := cmd.Flags().GetString("leader-name")
	if leaderNamespace == "" {
		leaderNamespace = os.Getenv("POD_NAMESPACE")
	}
	useLeader := leaderEnabled && leader.IsInCluster() && leaderNamespace != ""

	startSideEffects := func(leaderCtx context.Context) {
		if scanInterval > 0 {
			contexts, err := resolveScheduleContexts(kubeconfigPath, contextNames, allContexts)
			if err != nil {
				log.Warn("scheduler: resolve contexts failed", logutil.ErrorField(err))
			} else {
				go srv.StartScheduler(leaderCtx, scanInterval, contexts)
			}
		}
		if enabled, _ := cmd.Flags().GetBool("controller"); enabled {
			ctrlNS, _ := cmd.Flags().GetString("controller-namespace")
			ctrlContext, _ := cmd.Flags().GetString("controller-context")
			ctrlPoll, _ := cmd.Flags().GetDuration("controller-poll")
			dyn, err := controller.DynamicClient(kubeconfigPath, ctrlContext)
			if err != nil {
				log.Warn("controller: dynamic client failed", logutil.ErrorField(err))
				return
			}
			ctrl := controller.New(controller.Config{
				Dynamic:      dyn,
				Namespace:    ctrlNS,
				Runner:       srv,
				Log:          log,
				PollInterval: ctrlPoll,
			})
			go func() {
				if err := ctrl.Run(leaderCtx); err != nil {
					log.Warn("controller stopped", logutil.ErrorField(err))
				}
			}()
		}
	}

	if useLeader {
		go func() {
			err := leader.Run(ctx, leader.Config{
				Namespace: leaderNamespace,
				Name:      leaderName,
				Identity:  os.Getenv("POD_NAME"),
				Log:       log,
			}, leader.Callbacks{
				OnStartedLeading: startSideEffects,
			})
			if err != nil {
				log.Warn("leader election failed; falling back to single-instance mode",
					logutil.ErrorField(err))
				startSideEffects(ctx)
			}
		}()
	} else {
		startSideEffects(ctx)
	}

	if retain, _ := cmd.Flags().GetDuration("audit-retention"); retain > 0 {
		srv.StartAuditRetention(ctx, retain)
	}

	if admAddr, _ := cmd.Flags().GetString("admission-addr"); admAddr != "" {
		mode := admission.ModeAdvisory
		if v, _ := cmd.Flags().GetString("admission-mode"); strings.EqualFold(v, "enforce") {
			mode = admission.ModeEnforce
		}
		certPath, _ := cmd.Flags().GetString("admission-cert")
		keyPath, _ := cmd.Flags().GetString("admission-key")
		dns, _ := cmd.Flags().GetStringSlice("admission-dns")
		admServer, err := admission.NewServer(admission.ServerConfig{
			Addr:     admAddr,
			CertPath: certPath,
			KeyPath:  keyPath,
			DNSNames: dns,
			Log:      log,
			Handler: &admission.Handler{
				Provider: admission.NewStoreBaselineProvider(s, 60*time.Second),
				Checks:   admission.DefaultChecks(),
				Mode:     mode,
				Log:      log,
			},
		})
		if err != nil {
			return fmt.Errorf("admission server: %w", err)
		}
		go func() {
			if err := admServer.Run(ctx); err != nil {
				log.Warn("admission server stopped", logutil.ErrorField(err))
			}
		}()
		fmt.Fprintf(cmd.ErrOrStderr(), "admission webhook listening on %s (mode=%s)\n", admAddr, mode)
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

// openServeStore opens whichever backend --db / --db-driver point at, falling
// back to an in-memory SQLite database when --demo is set without --db so
// reviewers can preview the UI with a single command. Outside demo mode a
// missing --db is still an error.
func openServeStore(cmd *cobra.Command, demo bool) (store.Store, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" && demo {
		return store.NewSQLite(":memory:")
	}
	return openAnyStore(cmd)
}
