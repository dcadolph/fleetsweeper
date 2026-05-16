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

	"github.com/dcadolph/fleetsweeper/internal/kube"
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
		store:          cfg.Store,
		registry:       cfg.Registry,
		log:            cfg.Log,
		mux:            http.NewServeMux(),
		kubeconfigPath: cfg.KubeconfigPath,
		workers:        cfg.Workers,
		authToken:      cfg.AuthToken,
		insecure:       cfg.Insecure,
		corsOrigins:    cfg.CORSOrigins,
		demo:           cfg.Demo,
		ctx:            ctx,
		cancel:         cancel,
	}

	s.routes()
	return s
}

// routes registers all API endpoints, health checks, and the static file handler.
func (s *Server) routes() {
	api := http.NewServeMux()
	api.HandleFunc("GET /scans", s.handleListScans)
	api.HandleFunc("GET /scans/{id}", s.handleGetScan)
	api.HandleFunc("GET /scans/{id}/report", s.handleGetScanReport)
	api.HandleFunc("POST /scans", s.handleTriggerScan)
	api.HandleFunc("GET /clusters", s.handleListClusters)
	api.HandleFunc("GET /clusters/{name}/detail", s.handleGetClusterDetail)
	api.HandleFunc("GET /groups", s.handleListGroups)
	api.HandleFunc("POST /groups", s.handleCreateGroup)
	api.HandleFunc("DELETE /groups/{name}", s.handleDeleteGroup)
	api.HandleFunc("GET /trends", s.handleGetTrends)
	api.HandleFunc("GET /trends/{cluster}", s.handleGetClusterTrends)
	api.HandleFunc("GET /outliers", s.handleGetOutliers)
	api.HandleFunc("GET /capacity", s.handleGetCapacity)
	api.HandleFunc("GET /geo", s.handleGetGeo)
	api.HandleFunc("GET /locations", s.handleListLocations)
	api.HandleFunc("PUT /locations/{cluster}", s.handleSetLocation)
	api.HandleFunc("DELETE /locations/{cluster}", s.handleDeleteLocation)

	authed := bearerAuthMiddleware(s.authToken, s.insecure, api)
	withCORS := corsMiddleware(s.corsOrigins, authed)
	s.mux.Handle("/api/", http.StripPrefix("/api", jsonMiddleware(withCORS)))

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)

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

// Shutdown gracefully stops both HTTP servers and cancels the server context.
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
	return firstErr
}

// StartScheduler begins periodic scanning at the given interval. It runs until
// the server context is cancelled. The supplied ctx is used only for the
// initial scan; subsequent ticks use the server context so a cancelled parent
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
		s.log.Error("scheduled scan: save failed", zap.Error(err))
		return
	}
	s.scansOK.Add(1)
	s.log.Info("scheduled scan complete", zap.String("scan_id", scanID))
}

// runScanners executes all scanners against all clients concurrently.
func runScanners(ctx context.Context, clients []*kube.Client, scanners map[string]scanner.Scanner, workers int, log *zap.Logger) map[string]map[string]scanner.Result {
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

				res, err := s.Scan(ctx, c)
				if err != nil {
					log.Warn("scanner failed", zap.String("context", c.Context), zap.Error(err))
					return
				}

				mu.Lock()
				results[c.Context][scanName] = res
				mu.Unlock()
			}(client, name, sc)
		}
	}

	wg.Wait()
	return results
}

// handleMetrics returns a minimal Prometheus exposition with the counters the
// server maintains internally. A full client_golang integration was deferred
// to keep distribution lean; this still gives operators something to scrape.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	scansOk, scansErr := s.scanCounts()
	fmt.Fprintf(w, "# HELP fleetsweeper_scans_total Total scans executed by result.\n")
	fmt.Fprintf(w, "# TYPE fleetsweeper_scans_total counter\n")
	fmt.Fprintf(w, "fleetsweeper_scans_total{result=\"success\"} %d\n", scansOk)
	fmt.Fprintf(w, "fleetsweeper_scans_total{result=\"error\"} %d\n", scansErr)
}

// scanCounts returns the success and error counts since startup.
func (s *Server) scanCounts() (int64, int64) {
	return s.scansOK.Load(), s.scansErr.Load()
}
