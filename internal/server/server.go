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

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
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

	// admissionMetrics holds the admission webhook counters, or nil.
	admissionMetrics *admission.Metrics
	// kubeconfigPath is the kubeconfig file path used for triggered and scheduled scans.
	kubeconfigPath string
	// workers is the maximum concurrent operations for scans.
	workers int

	// authToken is the bearer token required for mutating endpoints.
	authToken string
	// insecure disables auth entirely when true. It is the one place auth is decided off,
	// and it is set for demo mode too, because the demo world is sealed and synthetic.
	insecure bool
	// corsOrigins is the allowlist of origins permitted to make cross-origin requests.
	corsOrigins []string
	// demo, when true, serves synthetic geo data so the globe works without
	// a real fleet, and runs scans against the synthetic fleet.
	demo bool
	// demoLiveScans counts the demo scans run since startup, which picks the
	// scripted change each one carries.
	demoLiveScans atomic.Int64

	// httpServer is the public http.Server. New builds it so Shutdown never races its creation.
	httpServer *http.Server
	// adminServer is the pprof and metrics http.Server. Nil when no admin address is configured.
	adminServer *http.Server

	// ctx is the server-scoped context used by goroutines that outlive a single request.
	ctx context.Context
	// cancel cancels ctx when the server shuts down.
	cancel context.CancelFunc

	// scanMu serializes scan execution; only one scan may run at a time.
	scanMu sync.Mutex
	// schedulerSlot holds a token while a scheduler runs, so at most one runs per process.
	schedulerSlot chan struct{}
	// scheduledScan runs one scheduled scan. Tests replace it to observe the scheduler.
	scheduledScan func(ctx context.Context, contexts []string)
	// dispatchSem bounds concurrent Slack and webhook deliveries to dispatchWorkers.
	dispatchSem chan struct{}
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
	// metricsCache memoizes the rebuilt report behind /metrics so two scrapes
	// within a TTL window do not trigger duplicate report builds.
	metricsCache metricsCache
	// reports caches reports rebuilt from stored scans for the read-only series endpoints.
	reports reportCache
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
	// rateLimiter throttles requests per client address. Nil disables limiting.
	rateLimiter *rateLimiter
	// trustedProxyHeader names the header a trusted reverse proxy sets to the client address.
	// Empty keys the rate limiter by the transport's remote address.
	trustedProxyHeader string
	// keyTouchMu guards keyTouches.
	keyTouchMu sync.Mutex
	// keyTouches records when each API key's last-used time was last written, so a busy key
	// writes at most once per keyTouchInterval.
	keyTouches map[string]time.Time
}

// Config holds server configuration.
type Config struct {
	// Addr is the listen address for the public API and UI. Empty means ":8080".
	Addr string
	// AdminAddr is the listen address for pprof and metrics. Empty disables the admin server.
	AdminAddr string
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
	// Insecure disables authentication entirely when true. Demo implies it.
	Insecure bool
	// CORSOrigins is the explicit allowlist of permitted cross-origin Origins.
	// Wildcard is intentionally not supported.
	CORSOrigins []string
	// Demo, when true, causes /api/geo to return synthetic fleet data so the
	// globe can be previewed without any real clusters or scans, and a
	// triggered scan scans the synthetic fleet instead of the kubeconfig. Demo
	// turns authentication off, since nothing in the demo reaches a real cluster.
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
	// ReadRPM is the per-client budget for GET/HEAD/OPTIONS requests,
	// keyed by client address. Zero disables read limiting; 600 (10 per
	// second per client) is a sensible start.
	ReadRPM int
	// WriteRPM is the per-client budget for mutating requests, keyed by
	// client address. Zero disables write limiting; 60 (one per second
	// per client) is a sensible start.
	WriteRPM int
	// TrustedProxyHeader, when set, names the header (for example X-Forwarded-For) a trusted
	// reverse proxy uses to carry the client address. The rate limiter keys on its last entry.
	// Leave it empty unless every request arrives through that proxy, since clients can set
	// the header themselves.
	TrustedProxyHeader string
	// AdmissionMetrics, when non-nil, has its counters written on /metrics.
	AdmissionMetrics *admission.Metrics
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
		admissionMetrics:      cfg.AdmissionMetrics,
		store:                 cfg.Store,
		registry:              cfg.Registry,
		log:                   cfg.Log,
		mux:                   http.NewServeMux(),
		kubeconfigPath:        cfg.KubeconfigPath,
		workers:               cfg.Workers,
		authToken:             cfg.AuthToken,
		insecure:              cfg.Insecure || cfg.Demo,
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
		trustedProxyHeader:    cfg.TrustedProxyHeader,
		keyTouches:            map[string]time.Time{},
		dispatchSem:           make(chan struct{}, dispatchWorkers),
		schedulerSlot:         make(chan struct{}, 1),
	}
	s.scheduledScan = s.runScheduledScan

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
	s.httpServer = s.newHTTPServer(cfg.Addr)
	s.adminServer = s.newAdminServer(cfg.AdminAddr)
	s.initOTelMetricsOrLog()
	return s
}

// newHTTPServer builds the public http.Server on addr with full timeouts.
func (s *Server) newHTTPServer(addr string) *http.Server {
	if addr == "" {
		addr = ":8080"
	}
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// newAdminServer builds the pprof and metrics http.Server on addr, or returns nil when addr is
// empty.
func (s *Server) newAdminServer(addr string) *http.Server {
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
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// Handler returns the root HTTP handler with request logging applied, exactly as
// ListenAndServe serves it, so the server can be embedded behind another router or
// driven in tests without binding a socket.
func (s *Server) Handler() http.Handler {
	return loggingMiddleware(s.log, securityHeaders(s.mux))
}

// route is one HTTP endpoint the server serves: its method, its path, and its
// handler. The API table and the root table are the only places routes are
// declared, so a test can hold them against openapi.yaml.
type route struct {
	// Method is the HTTP method.
	Method string
	// Path is the request path pattern. API paths are relative to /api.
	Path string
	// Handler serves the route.
	Handler http.HandlerFunc
}

// apiRoutes returns every endpoint served under /api.
func (s *Server) apiRoutes() []route {
	return []route{
		{Method: http.MethodGet, Path: "/scans", Handler: s.handleListScans},
		{Method: http.MethodGet, Path: "/scans/{id}", Handler: s.handleGetScan},
		{Method: http.MethodGet, Path: "/scans/{id}/report", Handler: s.handleGetScanReport},
		{Method: http.MethodGet, Path: "/scans/{id}/seal", Handler: s.handleGetScanSeal},
		{Method: http.MethodPost, Path: "/scans", Handler: s.handleTriggerScan},
		{Method: http.MethodGet, Path: "/clusters", Handler: s.handleListClusters},
		{Method: http.MethodGet, Path: "/clusters/{name}/detail", Handler: s.handleGetClusterDetail},
		{Method: http.MethodGet, Path: "/clusters/{name}/timeline", Handler: s.handleClusterTimeline},
		{Method: http.MethodGet, Path: "/clusters/{name}/tags", Handler: s.handleListClusterTags},
		{Method: http.MethodPut, Path: "/clusters/{name}/tags/{key}", Handler: s.handleSetClusterTag},
		{Method: http.MethodDelete, Path: "/clusters/{name}/tags/{key}", Handler: s.handleDeleteClusterTag},
		{Method: http.MethodGet, Path: "/tags", Handler: s.handleListAllTags},
		{Method: http.MethodGet, Path: "/groups", Handler: s.handleListGroups},
		{Method: http.MethodPost, Path: "/groups", Handler: s.handleCreateGroup},
		{Method: http.MethodDelete, Path: "/groups/{name}", Handler: s.handleDeleteGroup},
		{Method: http.MethodGet, Path: "/trends", Handler: s.handleGetTrends},
		{Method: http.MethodGet, Path: "/trends/{cluster}", Handler: s.handleGetClusterTrends},
		{Method: http.MethodGet, Path: "/outliers", Handler: s.handleGetOutliers},
		{Method: http.MethodGet, Path: "/cohorts", Handler: s.handleGetCohorts},
		{Method: http.MethodGet, Path: "/capacity", Handler: s.handleGetCapacity},
		{Method: http.MethodGet, Path: "/forecast/fleet-score", Handler: s.handleGetFleetScoreForecast},
		{Method: http.MethodGet, Path: "/forecast/clusters", Handler: s.handleGetClusterForecasts},
		{Method: http.MethodGet, Path: "/cost", Handler: s.handleGetCost},
		{Method: http.MethodGet, Path: "/integrations", Handler: s.handleGetIntegrations},
		{Method: http.MethodGet, Path: "/acks", Handler: s.handleListAcks},
		{Method: http.MethodGet, Path: "/findings/timeline", Handler: s.handleFindingsTimeline},
		{Method: http.MethodGet, Path: "/findings/persistence", Handler: s.handleFindingsPersistence},
		{Method: http.MethodPost, Path: "/findings/{fingerprint}/ack", Handler: s.handleCreateAck},
		{Method: http.MethodDelete, Path: "/findings/{fingerprint}/ack", Handler: s.handleDeleteAck},
		{Method: http.MethodPost, Path: "/alerts/{fingerprint}/ack", Handler: s.handleAckAlert},
		{Method: http.MethodPost, Path: "/webhooks/scan-trigger", Handler: s.handleWebhookScanTrigger},
		{Method: http.MethodPost, Path: "/webhooks/alertmanager", Handler: s.handleAlertManagerWebhook},
		{Method: http.MethodPost, Path: "/webhooks/falco", Handler: s.handleFalcoWebhook},
		{Method: http.MethodGet, Path: "/alerts", Handler: s.handleListAlerts},
		{Method: http.MethodGet, Path: "/geo", Handler: s.handleGetGeo},
		{Method: http.MethodGet, Path: "/contexts", Handler: s.handleListContexts},
		{Method: http.MethodGet, Path: "/locations", Handler: s.handleListLocations},
		{Method: http.MethodPut, Path: "/locations/{cluster}", Handler: s.handleSetLocation},
		{Method: http.MethodDelete, Path: "/locations/{cluster}", Handler: s.handleDeleteLocation},
		{Method: http.MethodGet, Path: "/admin/keys", Handler: s.handleAdminListKeys},
		{Method: http.MethodPost, Path: "/admin/keys", Handler: s.handleAdminCreateKey},
		{Method: http.MethodDelete, Path: "/admin/keys/{id}", Handler: s.handleAdminRevokeKey},
		{Method: http.MethodGet, Path: "/admin/audit", Handler: s.handleAdminListAudit},
		{Method: http.MethodGet, Path: "/admin/whoami", Handler: s.handleAdminWhoami},
		{Method: http.MethodGet, Path: "/admin/system", Handler: s.handleAdminSystem},
		{Method: http.MethodGet, Path: "/scanners", Handler: s.handleListScanners},
		{Method: http.MethodGet, Path: "/distributions", Handler: s.handleGetDistributions},
		{Method: http.MethodGet, Path: "/distributions/history", Handler: s.handleGetDistributionHistory},
		{Method: http.MethodGet, Path: "/score/attribution", Handler: s.handleGetScoreAttribution},
		{Method: http.MethodGet, Path: "/drift", Handler: s.handleGetDrift},
		{Method: http.MethodGet, Path: "/cohorts/map", Handler: s.handleGetCohortMap},
		{Method: http.MethodPost, Path: "/whatif", Handler: s.handleWhatIf},
		{Method: http.MethodGet, Path: "/events", Handler: s.handleEventsStream},
	}
}

// rootRoutes returns the endpoints served outside /api that openapi.yaml
// documents. The cinematic redirect and the static files are left out.
func (s *Server) rootRoutes() []route {
	return []route{
		{Method: http.MethodGet, Path: "/healthz", Handler: s.handleHealthz},
		{Method: http.MethodGet, Path: "/readyz", Handler: s.handleReadyz},
		{Method: http.MethodGet, Path: "/openapi.yaml", Handler: s.handleOpenAPI},
		{Method: http.MethodGet, Path: "/oidc/login", Handler: s.handleOIDCLogin},
		{Method: http.MethodGet, Path: "/oidc/callback", Handler: s.handleOIDCCallback},
		{Method: http.MethodGet, Path: "/oidc/logout", Handler: s.handleOIDCLogout},
	}
}

// serveChartJS serves the vendored Chart.js build the report package embeds, so the dashboard
// and the standalone report load the same bytes.
func serveChartJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(report.ChartJS)
}

// routes registers all API endpoints, health checks, and the static file handler.
func (s *Server) routes() {
	api := http.NewServeMux()
	for _, r := range s.apiRoutes() {
		api.HandleFunc(r.Method+" "+r.Path, r.Handler)
	}

	audited := s.auditMiddleware(api)
	authed := s.authMiddleware(audited)
	limited := s.rateLimitMiddleware(authed)
	withCORS := corsMiddleware(s.corsOrigins, limited)
	s.mux.Handle("/api/", http.StripPrefix("/api", jsonMiddleware(withCORS)))

	for _, r := range s.rootRoutes() {
		s.mux.HandleFunc(r.Path, r.Handler)
	}
	s.mux.HandleFunc("/cinematic", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/cinematic.html", http.StatusFound)
	})

	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("server: static fs: %v", err))
	}
	s.mux.HandleFunc("GET /vendor/chart.min.js", serveChartJS)
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

// ListenAndServe serves the public API and UI on Config.Addr until Shutdown. It returns nil
// after a graceful shutdown, including one that happens before it is called.
func (s *Server) ListenAndServe() error {
	s.log.Info("starting server", zap.String("addr", s.httpServer.Addr))
	switch {
	case s.demo:
		s.log.Info("demo mode, auth off: the synthetic fleet is open to every visitor")
	case s.insecure:
		s.log.Warn("INSECURE MODE: HTTP API is open and can scan your kubeconfig contexts")
	case s.authToken == "":
		s.log.Warn("auth disabled: mutating endpoints will return 403; pass --auth-token to enable, or --insecure to disable auth entirely")
	}
	return ignoreServerClosed(s.httpServer.ListenAndServe())
}

// ListenAndServeAdmin serves pprof and metrics on Config.AdminAddr, intended for an internal
// address that is not exposed to untrusted networks. It is a no-op when no admin address is
// configured.
func (s *Server) ListenAndServeAdmin() error {
	if s.adminServer == nil {
		return nil
	}
	s.log.Info("starting admin server", zap.String("addr", s.adminServer.Addr))
	return ignoreServerClosed(s.adminServer.ListenAndServe())
}

// ignoreServerClosed maps http.ErrServerClosed, the result of a graceful shutdown, to nil.
func ignoreServerClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops both HTTP servers, cancels the server context,
// and waits for fire-and-forget background goroutines to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	firstErr := s.httpServer.Shutdown(ctx)
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

// StartScheduler scans contexts every interval, starting immediately, and blocks until ctx or
// the server context is canceled. Under leader election ctx is the leadership term, so losing
// the lease stops the scheduler. At most one scheduler runs per process: a call made while an
// earlier one is still winding down waits for it to return, so a replica that loses and
// regains leadership never runs two.
func (s *Server) StartScheduler(ctx context.Context, interval time.Duration, contexts []string) {
	if interval <= 0 || len(contexts) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()

	select {
	case s.schedulerSlot <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.schedulerSlot }()

	s.log.Info("scheduler started",
		zap.Duration("interval", interval),
		zap.Int("contexts", len(contexts)),
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for ctx.Err() == nil {
		s.scheduledScan(ctx, contexts)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	s.log.Info("scheduler stopped")
}

// runScheduledScan executes one scheduled scan of every registered scanner.
func (s *Server) runScheduledScan(ctx context.Context, contexts []string) {
	_, _, _ = s.executeScan(ctx, scanRequest{Source: scanSourceScheduled, Contexts: contexts, Emit: emitAll})
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
