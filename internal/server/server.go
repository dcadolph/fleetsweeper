package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
	"github.com/dcadolph/fleetsweeper/internal/tracing"
)

//go:embed static
var staticFS embed.FS

// Server wraps the HTTP server with its dependencies.
type Server struct {
	// store is the persistence backend.
	store store.Store
	// registry is the scanner registry.
	registry *scanner.Registry
	// log is the structured logger.
	log *zap.Logger
	// mux is the primary HTTP request multiplexer.
	mux *http.ServeMux

	// kubeconfigPath is the kubeconfig file path used for triggered and scheduled scans.
	kubeconfigPath string
	// workers is the maximum concurrent operations for scans.
	workers int

	// authToken is the bearer token required for mutating endpoints.
	authToken string
	// insecure disables auth entirely when true.
	insecure bool
	// corsOrigins is the allowlist of origins permitted to make cross-origin requests.
	corsOrigins []string
	// demo, when true, serves synthetic geo data so the globe works without
	// a real fleet.
	demo bool

	// httpServer is the underlying http.Server used by ListenAndServe and Shutdown.
	httpServer *http.Server
	// adminServer is an optional second http.Server bound to a separate admin address.
	adminServer *http.Server

	// ctx is the server-scoped context used by goroutines that outlive a single request.
	ctx context.Context
	// cancel cancels ctx when the server shuts down.
	cancel context.CancelFunc

	// scanMu serializes scan execution; only one scan may run at a time.
	scanMu sync.Mutex
	// scanBusy is set while a scan is in flight; used to short-circuit trigger
	// requests with a 429 instead of unbounded queueing.
	scanBusy atomic.Bool
	// scansOK counts successful scan completions since startup.
	scansOK atomic.Int64
	// scansErr counts failed scan completions since startup.
	scansErr atomic.Int64
	// lastScanDuration holds the most recent scan duration in nanoseconds for
	// the /metrics gauge.
	lastScanDuration atomic.Int64
	// alertsReceivedAM is the count of AlertManager alerts persisted since startup.
	alertsReceivedAM atomic.Int64
	// alertsReceivedFalco is the count of Falco events persisted since startup.
	alertsReceivedFalco atomic.Int64
	// metricsCache memoises the rebuilt report behind /metrics so two scrapes
	// within a TTL window do not trigger duplicate report builds.
	metricsCache metricsCache
	// slackWebhookURL, when non-empty, receives new critical findings as
	// formatted Slack messages.
	slackWebhookURL string
	// slackNotifiedKeys remembers fingerprints of findings already sent to
	// Slack so a repeated scan does not re-notify on unchanged criticals.
	slackNotifiedKeys map[string]time.Time
	// slackMu serializes mutations of slackNotifiedKeys.
	slackMu sync.Mutex
	// fleetDriftOutputDir, when non-empty, is the local directory the server
	// writes FleetDriftReport YAMLs to after every scan.
	fleetDriftOutputDir string
	// policyReportOutputDir, when non-empty, is the local directory the server
	// writes wgpolicyk8s.io PolicyReport YAMLs to after every scan.
	policyReportOutputDir string
	// policyReportNamespace places emitted PolicyReports.
	policyReportNamespace string
	// costCSVPath is the local CSV file mapping clusters to cost-per-period
	// figures. Empty disables cost correlation.
	costCSVPath string
	// otel holds OTel metric instruments registered against the global meter.
	otel otelInitField
	// webhookConfigPath is the operator-supplied path to the outbound
	// webhook YAML. Empty disables outbound webhook dispatch.
	webhookConfigPath string
	// webhookDispatcher is the parsed subscriber list ready to fire.
	webhookDispatcher *webhookDispatcher
	// webhookSecret is the HMAC-SHA256 shared secret for inbound scan
	// triggers. Empty disables the inbound endpoint.
	webhookSecret string
	// sealKey is the HMAC-SHA256 secret used to sign saved scan reports.
	sealKey string
	// events fans scan-complete and key-revoke events to SSE subscribers.
	events *eventBus
	// bg tracks fire-and-forget background goroutines so Close can wait
	// for them. Tests rely on this to avoid racing temp-dir cleanup
	// against in-flight database writes.
	bg sync.WaitGroup
	// oidc holds the OIDC runtime when --oidc-issuer-url is set. Nil
	// when OIDC is not configured; the auth middleware falls back to
	// bearer-only authentication in that case.
	oidc *oidcRuntime
	// rateLimiter throttles requests per actor (or per remote address).
	// Nil disables limiting.
	rateLimiter *rateLimiter
}

// Config holds server configuration.
type Config struct {
	// Store is the database backend.
	Store store.Store
	// Registry is the scanner registry.
	Registry *scanner.Registry
	// Log is the zap logger.
	Log *zap.Logger
	// KubeconfigPath is the kubeconfig file path for scans.
	KubeconfigPath string
	// Workers is the max concurrent operations for scans.
	Workers int
	// AuthToken is the bearer token required for mutating endpoints. When
	// empty and Insecure is false, mutating endpoints return 403.
	AuthToken string
	// Insecure disables authentication entirely when true.
	Insecure bool
	// CORSOrigins is the explicit allowlist of permitted cross-origin Origins.
	// Wildcard is intentionally not supported.
	CORSOrigins []string
	// Demo, when true, causes /api/geo to return synthetic fleet data so the
	// globe can be previewed without any real clusters or scans. Other
	// endpoints behave normally; demo mode is read-only and additive.
	Demo bool
	// SlackWebhookURL, when non-empty, is the incoming-webhook URL that
	// receives new critical findings.
	SlackWebhookURL string
	// FleetDriftOutputDir, when non-empty, is a local directory the server
	// writes FleetDriftReport YAMLs into after every scan. One file per
	// cluster, overwritten in place so the directory tracks the latest scan.
	FleetDriftOutputDir string
	// PolicyReportOutputDir, when non-empty, is a local directory the server
	// writes wgpolicyk8s.io PolicyReport YAMLs to after every scan.
	PolicyReportOutputDir string
	// PolicyReportNamespace is the namespace placed on emitted PolicyReports.
	// Defaults to "fleetsweeper" when empty.
	PolicyReportNamespace string
	// CostCSVPath, when non-empty, points at a CSV mapping clusters to costs.
	// Loaded once at startup and refreshed on a periodic ticker so dashboard
	// cost correlation reflects current billing without a restart.
	CostCSVPath string
	// WebhookConfigPath, when non-empty, points at a YAML file of outbound
	// HTTP subscribers. See internal/webhooks for the schema.
	WebhookConfigPath string
	// WebhookSecret, when non-empty, is the HMAC-SHA256 shared secret an
	// inbound webhook caller must use to authenticate scan-trigger calls.
	WebhookSecret string
	// SealKey, when non-empty, is the HMAC-SHA256 secret used to sign every
	// saved scan report. Sealed scans can be verified later with
	// `fleetsweeper verify`.
	SealKey string
	// OIDC configures browser SSO. When zero-valued the server runs in
	// bearer-only mode.
	OIDC OIDCConfig
	// ReadRPM is the per-actor budget for GET/HEAD/OPTIONS requests.
	// Zero disables read limiting; recommended default is 600 (10 per
	// second per actor).
	ReadRPM int
	// WriteRPM is the per-actor budget for mutating requests. Zero
	// disables write limiting; recommended default is 60 (one per
	// second per actor).
	WriteRPM int
}

// New creates a Server. Panics if store, registry, or log is nil.
func New(cfg Config) *Server {
	if cfg.Store == nil {
		panic("server: Store required")
	}
	if cfg.Registry == nil {
		panic("server: Registry required")
	}
	if cfg.Log == nil {
		panic("server: Log required")
	}
	if cfg.Workers == 0 {
		cfg.Workers = 5
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		store:                 cfg.Store,
		registry:              cfg.Registry,
		log:                   cfg.Log,
		mux:                   http.NewServeMux(),
		kubeconfigPath:        cfg.KubeconfigPath,
		workers:               cfg.Workers,
		authToken:             cfg.AuthToken,
		insecure:              cfg.Insecure,
		corsOrigins:           cfg.CORSOrigins,
		demo:                  cfg.Demo,
		ctx:                   ctx,
		cancel:                cancel,
		slackWebhookURL:       cfg.SlackWebhookURL,
		slackNotifiedKeys:     map[string]time.Time{},
		fleetDriftOutputDir:   cfg.FleetDriftOutputDir,
		policyReportOutputDir: cfg.PolicyReportOutputDir,
		policyReportNamespace: cfg.PolicyReportNamespace,
		costCSVPath:           cfg.CostCSVPath,
	}

	s.setupWebhooks(cfg.WebhookConfigPath)
	s.webhookSecret = cfg.WebhookSecret
	s.sealKey = cfg.SealKey
	s.events = newEventBus()

	if rt, err := initOIDC(s.ctx, cfg.OIDC, s.log); err != nil {
		s.log.Warn("oidc init failed; continuing with bearer-only auth", zap.Error(err))
	} else {
		s.oidc = rt
	}

	if cfg.ReadRPM > 0 || cfg.WriteRPM > 0 {
		s.rateLimiter = newRateLimiter(cfg.ReadRPM, cfg.WriteRPM)
	}

	s.routes()
	s.initOTelMetricsOrLog()
	return s
}

// routes registers all API endpoints, health checks, and the static file handler.
func (s *Server) routes() {
	api := http.NewServeMux()
	api.HandleFunc("GET /scans", s.handleListScans)
	api.HandleFunc("GET /scans/{id}", s.handleGetScan)
	api.HandleFunc("GET /scans/{id}/report", s.handleGetScanReport)
	api.HandleFunc("GET /scans/{id}/seal", s.handleGetScanSeal)
	api.HandleFunc("POST /scans", s.handleTriggerScan)
	api.HandleFunc("GET /clusters", s.handleListClusters)
	api.HandleFunc("GET /clusters/{name}/detail", s.handleGetClusterDetail)
	api.HandleFunc("GET /clusters/{name}/timeline", s.handleClusterTimeline)
	api.HandleFunc("GET /clusters/{name}/tags", s.handleListClusterTags)
	api.HandleFunc("PUT /clusters/{name}/tags/{key}", s.handleSetClusterTag)
	api.HandleFunc("DELETE /clusters/{name}/tags/{key}", s.handleDeleteClusterTag)
	api.HandleFunc("GET /tags", s.handleListAllTags)
	api.HandleFunc("GET /groups", s.handleListGroups)
	api.HandleFunc("POST /groups", s.handleCreateGroup)
	api.HandleFunc("DELETE /groups/{name}", s.handleDeleteGroup)
	api.HandleFunc("GET /trends", s.handleGetTrends)
	api.HandleFunc("GET /trends/{cluster}", s.handleGetClusterTrends)
	api.HandleFunc("GET /outliers", s.handleGetOutliers)
	api.HandleFunc("GET /cohorts", s.handleGetCohorts)
	api.HandleFunc("GET /capacity", s.handleGetCapacity)
	api.HandleFunc("GET /forecast/fleet-score", s.handleGetFleetScoreForecast)
	api.HandleFunc("GET /forecast/clusters", s.handleGetClusterForecasts)
	api.HandleFunc("GET /cost", s.handleGetCost)
	api.HandleFunc("GET /integrations", s.handleGetIntegrations)
	api.HandleFunc("GET /acks", s.handleListAcks)
	api.HandleFunc("POST /findings/{fingerprint}/ack", s.handleCreateAck)
	api.HandleFunc("DELETE /findings/{fingerprint}/ack", s.handleDeleteAck)
	api.HandleFunc("POST /alerts/{fingerprint}/ack", s.handleAckAlert)
	api.HandleFunc("POST /webhooks/scan-trigger", s.handleWebhookScanTrigger)
	api.HandleFunc("POST /webhooks/alertmanager", s.handleAlertManagerWebhook)
	api.HandleFunc("POST /webhooks/falco", s.handleFalcoWebhook)
	api.HandleFunc("GET /alerts", s.handleListAlerts)
	api.HandleFunc("GET /geo", s.handleGetGeo)
	api.HandleFunc("GET /contexts", s.handleListContexts)
	api.HandleFunc("GET /locations", s.handleListLocations)
	api.HandleFunc("PUT /locations/{cluster}", s.handleSetLocation)
	api.HandleFunc("DELETE /locations/{cluster}", s.handleDeleteLocation)
	api.HandleFunc("GET /admin/keys", s.handleAdminListKeys)
	api.HandleFunc("POST /admin/keys", s.handleAdminCreateKey)
	api.HandleFunc("DELETE /admin/keys/{id}", s.handleAdminRevokeKey)
	api.HandleFunc("GET /admin/audit", s.handleAdminListAudit)
	api.HandleFunc("GET /admin/whoami", s.handleAdminWhoami)
	api.HandleFunc("GET /admin/system", s.handleAdminSystem)
	api.HandleFunc("GET /events", s.handleEventsStream)

	audited := s.auditMiddleware(api)
	limited := s.rateLimitMiddleware(audited)
	authed := s.authMiddleware(limited)
	withCORS := corsMiddleware(s.corsOrigins, authed)
	s.mux.Handle("/api/", http.StripPrefix("/api", jsonMiddleware(withCORS)))

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/openapi.yaml", s.handleOpenAPI)
	s.mux.HandleFunc("/oidc/login", s.handleOIDCLogin)
	s.mux.HandleFunc("/oidc/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("/oidc/logout", s.handleOIDCLogout)
	s.mux.HandleFunc("/cinematic", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/cinematic.html", http.StatusFound)
	})

	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("server: static fs: %v", err))
	}
	s.mux.Handle("/", http.FileServer(http.FS(staticContent)))
}

// handleHealthz returns 200 if the process is alive.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleReadyz returns 200 if the store is reachable.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	pinger, ok := s.store.(interface {
		Ping(context.Context) error
	})
	if ok {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pinger.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "store unavailable"})
			return
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ListenAndServe starts the HTTP server on the given address with full timeouts.
func (s *Server) ListenAndServe(addr string) error {
	handler := loggingMiddleware(s.log, s.mux)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.log.Info("starting server", zap.String("addr", addr))
	if s.authToken == "" && !s.insecure {
		s.log.Warn("auth disabled: mutating endpoints will return 403; pass --auth-token to enable, or --insecure to disable auth entirely")
	}
	if s.insecure {
		s.log.Warn("INSECURE MODE: HTTP API is open and can scan your kubeconfig contexts")
	}
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ListenAndServeAdmin starts a separate HTTP server with pprof and a basic
// metrics endpoint, intended for an internal address that is not exposed to
// untrusted networks. When addr is empty this is a no-op.
func (s *Server) ListenAndServeAdmin(addr string) error {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	s.adminServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.log.Info("starting admin server", zap.String("addr", addr))
	err := s.adminServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops both HTTP servers, cancels the server context,
// and waits for fire-and-forget background goroutines to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	var firstErr error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			firstErr = err
		}
	}
	if s.adminServer != nil {
		if err := s.adminServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.bg.Wait()
	return firstErr
}

// Close is a convenience wrapper that cancels the server context and waits
// for background goroutines to drain. Used by tests and offline tooling.
func (s *Server) Close() {
	s.cancel()
	s.bg.Wait()
}

// StartScheduler begins periodic scanning at the given interval. It runs until
// the server context is canceled. The supplied ctx is used only for the
// initial scan; subsequent ticks use the server context so a canceled parent
// does not silently kill the scheduler.
func (s *Server) StartScheduler(_ context.Context, interval time.Duration, contexts []string) {
	if interval <= 0 || len(contexts) == 0 {
		return
	}

	s.log.Info("scheduler started",
		zap.Duration("interval", interval),
		zap.Int("contexts", len(contexts)),
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.runScheduledScan(s.ctx, contexts)
	for {
		select {
		case <-s.ctx.Done():
			s.log.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.runScheduledScan(s.ctx, contexts)
		}
	}
}

// runScheduledScan executes a full scan and stores the results under the
// server-scoped context.
func (s *Server) runScheduledScan(ctx context.Context, contexts []string) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	s.log.Info("scheduled scan starting", zap.Int("contexts", len(contexts)))
	started := time.Now()

	clients := kube.ConnectAll(ctx, s.kubeconfigPath, contexts, s.workers)
	if len(clients) == 0 {
		s.log.Warn("scheduled scan: no clusters reachable")
		return
	}

	results := runScanners(ctx, clients, s.registry.All(), s.workers, s.log)

	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	scanID, err := s.store.SaveScan(ctx, clusterNames, results)
	if err != nil {
		s.scansErr.Add(1)
		s.recordScanCompletion(false)
		s.log.Error("scheduled scan: save failed", zap.Error(err))
		return
	}
	s.scansOK.Add(1)
	s.recordScanDuration(time.Since(started))
	s.recordScanCompletion(true)
	s.log.Info("scheduled scan complete", zap.String("scan_id", scanID))
	rpt := report.Build(clusterNames, results)
	s.notifySlackForReport(ctx, rpt)
	s.writeFleetDriftIfConfigured(rpt, scanID)
	s.writePolicyReportIfConfigured(rpt, scanID)
	s.dispatchWebhooksIfConfigured(ctx, rpt)
	s.PublishEvent(EventScanComplete, map[string]any{
		"scan_id":  scanID,
		"clusters": len(clusterNames),
		"score":    rpt.FleetScore.Score,
		"grade":    rpt.FleetScore.Grade,
	})
}

// runScanners executes all scanners against all clients concurrently. Each
// scanner-cluster pair gets a child span under the caller's parent so OTel
// traces show the per-scanner fan-out, including which scanners failed.
func runScanners(ctx context.Context, clients []*kube.Client, scanners map[string]scanner.Scanner, workers int, log *zap.Logger) map[string]map[string]scanner.Result {
	ctx, rootSpan := tracing.Tracer().Start(ctx, "fleetsweeper.scan",
		trace.WithAttributes(
			attribute.Int("fleetsweeper.cluster_count", len(clients)),
			attribute.Int("fleetsweeper.scanner_count", len(scanners)),
		),
	)
	defer rootSpan.End()

	var mu sync.Mutex
	results := make(map[string]map[string]scanner.Result)
	for _, c := range clients {
		results[c.Context] = make(map[string]scanner.Result)
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, client := range clients {
		for name, sc := range scanners {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				continue
			}
			wg.Add(1)
			go func(c *kube.Client, scanName string, s scanner.Scanner) {
				defer wg.Done()
				defer func() { <-sem }()

				spanCtx, span := tracing.Tracer().Start(ctx, "fleetsweeper.scanner."+scanName,
					trace.WithAttributes(
						attribute.String("fleetsweeper.cluster", c.Context),
						attribute.String("fleetsweeper.scanner", scanName),
					),
				)
				defer span.End()

				res, err := s.Scan(spanCtx, c)
				if err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, "scanner failed")
					log.Warn("scanner failed", zap.String("context", c.Context), zap.Error(err))
					return
				}
				span.SetStatus(codes.Ok, "")

				mu.Lock()
				results[c.Context][scanName] = res
				mu.Unlock()
			}(client, name, sc)
		}
	}

	wg.Wait()
	return results
}

// handleMetrics emits the full Prometheus exposition. The implementation
// lives in metrics.go so this file stays focused on transport concerns.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.writeMetrics(r.Context(), w)
}

// scanCounts returns the success and error counts since startup.
func (s *Server) scanCounts() (int64, int64) {
	return s.scansOK.Load(), s.scansErr.Load()
}
