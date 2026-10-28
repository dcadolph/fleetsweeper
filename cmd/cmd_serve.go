package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

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
	Short: "Start the web UI and API server.",
	Example: "  fleetsweeper serve --demo\n" +
		"  fleetsweeper serve --db fleet.db --all-contexts --scan-interval 1h --auth-token \"$TOKEN\"",
	Long: "Launch a web server with an API and dashboard for browsing scan results, groups, trends, and outliers.",
	RunE: runServe,
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
	serveCmd.Flags().Bool("demo", false, "Serve a synthetic 26-cluster fleet from an in-memory store seeded with six days of scans. Every page has data without any real clusters. Does not take --db. Auth is off in demo mode.")
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
	serveCmd.Flags().String("admission-mode", "advisory", "Admission mode: advisory warns only, enforce denies pods that deviate from the fleet norm.")
	serveCmd.Flags().String("admission-baseline", "", "Path to a pinned baseline YAML file, in the format baseline export writes. The webhook checks pods against it instead of the latest scan. Empty uses the store.")
	serveCmd.Flags().Int("admission-stable-scans", admission.DefaultStableScans, "Consecutive recent scans a check's fleet norm must hold before enforce mode denies on it. Until then the pod is allowed with a warning. A pinned baseline is exempt.")
	serveCmd.Flags().String("oidc-issuer-url", "", "OIDC issuer discovery URL (for example https://accounts.google.com). Empty disables browser SSO.")
	serveCmd.Flags().String("oidc-client-id", "", "OIDC client ID registered with the identity provider.")
	serveCmd.Flags().String("oidc-client-secret", "", "OIDC client secret matching --oidc-client-id.")
	serveCmd.Flags().String("oidc-redirect-url", "", "Callback URL registered with the identity provider, ending in /oidc/callback.")
	serveCmd.Flags().StringSlice("oidc-scopes", []string{"openid", "email", "profile"}, "OIDC scopes to request. Repeat or comma-separate.")
	serveCmd.Flags().String("oidc-admin-claim", "", "ID token claim that grants the admin role, as name:value (for example groups:fleetsweeper-admins). Empty disables.")
	serveCmd.Flags().String("oidc-operator-claim", "", "ID token claim that grants the operator role, as name:value. Empty disables.")
	serveCmd.Flags().String("oidc-default-role", "viewer", "Role for signed-in users who match no claim mapping.")
	serveCmd.Flags().String("session-secret", "", "HMAC key that signs OIDC session cookies. Required when --oidc-issuer-url is set.")
	serveCmd.Flags().Duration("session-lifetime", 8*time.Hour, "How long an OIDC session cookie stays valid.")
	serveCmd.Flags().Int("rate-limit-read-rpm", 0, "Per-client budget of read requests per minute (600 is a sensible start). 0 disables read limiting.")
	serveCmd.Flags().Int("rate-limit-write-rpm", 0, "Per-client budget of mutating requests per minute (60 is a sensible start). 0 disables write limiting.")
	serveCmd.Flags().String("trusted-proxy-header", "", "Header a trusted reverse proxy sets to the client address (for example X-Forwarded-For). The rate limiter keys on its last entry. Leave empty unless every request passes through that proxy.")
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

	ctx, stop := context.WithCancel(cmdContext(cmd))
	defer stop()
	log := logutil.UnwrapLogger(ctx)
	if demo {
		started := time.Now()
		if err := server.SeedDemo(ctx, s, started.UTC().Truncate(time.Minute)); err != nil {
			return err
		}
		log.Info("demo fleet seeded", zap.Duration("took", time.Since(started)))
	}
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

	switch {
	case demo && authToken != "":
		log.Info("--auth-token ignored in demo mode")
	case !demo && authToken == "" && !insecure:
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
	trustedProxyHeader, _ := cmd.Flags().GetString("trusted-proxy-header")

	admMetrics := &admission.Metrics{}
	srv := server.New(server.Config{
		AdmissionMetrics:      admMetrics,
		Addr:                  addr,
		AdminAddr:             adminAddr,
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
		TrustedProxyHeader:    trustedProxyHeader,
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
	useLeader := leaderEnabled && kube.InCluster() && leaderNamespace != ""

	startSideEffects := func(leaderCtx context.Context) {
		if scanInterval > 0 {
			contexts, err := resolveScheduleContexts(kubeconfigPath, contextNames, allContexts)
			if err != nil {
				log.Warn("scheduler: resolve contexts failed", zap.Error(err))
			} else {
				go srv.StartScheduler(leaderCtx, scanInterval, contexts)
			}
		}
		if enabled, _ := cmd.Flags().GetBool("controller"); enabled {
			ctrlNS, _ := cmd.Flags().GetString("controller-namespace")
			ctrlContext, _ := cmd.Flags().GetString("controller-context")
			ctrlPoll, _ := cmd.Flags().GetDuration("controller-poll")
			dyn, events, err := controller.Clients(kubeconfigPath, ctrlContext)
			if err != nil {
				log.Warn("controller: client setup failed", zap.Error(err))
				return
			}
			ctrl := controller.New(controller.Config{
				Dynamic:      dyn,
				Events:       events,
				Namespace:    ctrlNS,
				Runner:       srv,
				Log:          log,
				PollInterval: ctrlPoll,
			})
			go func() {
				if err := ctrl.Run(leaderCtx); err != nil {
					log.Warn("controller stopped", zap.Error(err))
				}
			}()
		}
	}

	errCh := make(chan error, 2)
	if useLeader {
		go func() {
			err := campaign(ctx, log, func(ctx context.Context) error {
				return leader.Run(ctx, leader.Config{
					Namespace: leaderNamespace,
					Name:      leaderName,
					Identity:  os.Getenv("POD_NAME"),
					Log:       log,
				}, leader.Callbacks{
					OnStartedLeading: startSideEffects,
				})
			})
			if err != nil {
				errCh <- err
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
		pinPath, _ := cmd.Flags().GetString("admission-baseline")
		stableScans, _ := cmd.Flags().GetInt("admission-stable-scans")
		provider, err := newAdmissionProvider(pinPath, stableScans, s, log)
		if err != nil {
			return err
		}
		handler := admission.NewHandler(provider, admission.DefaultChecks(), mode, log)
		handler.StableScans = stableScans
		handler.Metrics = admMetrics
		admServer, err := admission.NewServer(admission.ServerConfig{
			Addr:     admAddr,
			CertPath: certPath,
			KeyPath:  keyPath,
			DNSNames: dns,
			Log:      log,
			Handler:  handler,
		})
		if err != nil {
			return fmt.Errorf("admission server: %w", err)
		}
		go func() {
			if err := admServer.Run(ctx); err != nil {
				log.Warn("admission server stopped", zap.Error(err))
			}
		}()
		fmt.Fprintf(cmd.ErrOrStderr(), "admission webhook listening on %s (mode=%s)\n", admAddr, mode)
	}

	if adminAddr != "" {
		go func() {
			if err := srv.ListenAndServeAdmin(); err != nil {
				log.Warn("admin server stopped", zap.Error(err))
			}
		}()
	}

	go func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "fleetsweeper server listening on %s\n", addr)
		errCh <- srv.ListenAndServe()
	}()

	var runErr error
	select {
	case runErr = <-errCh:
	case <-ctx.Done():
		fmt.Fprintln(cmd.ErrOrStderr(), "shutdown signal received; draining...")
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("shutdown: %w", err)
	}
	return runErr
}

// campaign runs one leader election term after another until ctx is canceled. Each term's
// side effects stop when that term's lease is lost, and the replica then stands for election
// again. An election error is returned rather than retried, because running the scheduler and
// controller without a lease would let every replica fire them at once.
func campaign(ctx context.Context, log *zap.Logger, term func(ctx context.Context) error) error {
	for ctx.Err() == nil {
		if err := term(ctx); err != nil {
			return fmt.Errorf("leader election: %w", err)
		}
		if ctx.Err() == nil {
			log.Info("leader: term ended; standing for election again")
		}
	}
	return nil
}

// newAdmissionProvider returns the webhook's baseline source: the pinned file at pinPath when
// one is given, else the store, derived from the last stableScans scans.
func newAdmissionProvider(pinPath string, stableScans int, s store.Store, log *zap.Logger) (admission.BaselineProvider, error) {
	if stableScans < 1 {
		return nil, fmt.Errorf("%w: got %d", ErrStableScans, stableScans)
	}
	if pinPath != "" {
		b, err := admission.LoadBaselineFile(pinPath)
		if err != nil {
			return nil, err
		}
		if !b.Sufficient() {
			log.Warn("pinned admission baseline is below the sample threshold: the webhook will not evaluate pods",
				zap.String("path", pinPath), zap.Int("sample_pods", b.SamplePods),
				zap.Int("sample_containers", b.SampleContainers))
		}
		return admission.NewPinnedBaselineProvider(b), nil
	}
	p := admission.NewStoreBaselineProvider(s, 60*time.Second)
	p.Log = log
	p.Depth = stableScans
	return p, nil
}

// resolveScheduleContexts determines which contexts to use for scheduled scans.
func resolveScheduleContexts(kubeconfigPath string, explicit []string, all bool) ([]string, error) {
	if all {
		return kube.AvailableContexts(kubeconfigPath)
	}
	return explicit, nil
}

// openServeStore opens whichever backend --db / --db-driver point at. --demo
// runs on an in-memory SQLite database the server seeds with the demo fleet,
// so it refuses a --db rather than write the demo into a real database.
// Outside demo mode a missing --db is still an error.
func openServeStore(cmd *cobra.Command, demo bool) (store.Store, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if demo {
		if dbPath != "" {
			return nil, ErrDemoDatabase
		}
		return store.NewSQLite(":memory:")
	}
	return openAnyStore(cmd)
}
