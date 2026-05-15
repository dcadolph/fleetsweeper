package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
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
	store    store.Store
	registry *scanner.Registry
	log      *zap.Logger
	mux      *http.ServeMux

	// Scan configuration for triggered/scheduled scans.
	kubeconfigPath string
	workers        int

	// scanMu protects concurrent scan execution.
	scanMu sync.Mutex
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

	s := &Server{
		store:          cfg.Store,
		registry:       cfg.Registry,
		log:            cfg.Log,
		mux:            http.NewServeMux(),
		kubeconfigPath: cfg.KubeconfigPath,
		workers:        cfg.Workers,
	}

	s.routes()
	return s
}

// routes registers all API endpoints and the static file handler.
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

	s.mux.Handle("/api/", http.StripPrefix("/api", corsMiddleware(jsonMiddleware(api))))

	// Static files for the SPA.
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("server: static fs: %v", err))
	}
	fileServer := http.FileServer(http.FS(staticContent))
	s.mux.Handle("/", fileServer)
}

// ListenAndServe starts the HTTP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	handler := loggingMiddleware(s.log, s.mux)
	s.log.Info("starting server", zap.String("addr", addr))
	return http.ListenAndServe(addr, handler)
}

// StartScheduler begins periodic scanning at the given interval. It runs until
// the context is cancelled.
func (s *Server) StartScheduler(ctx context.Context, interval time.Duration, contexts []string) {
	if interval <= 0 || len(contexts) == 0 {
		return
	}

	s.log.Info("scheduler started",
		zap.Duration("interval", interval),
		zap.Int("contexts", len(contexts)),
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start.
	s.runScheduledScan(ctx, contexts)

	for {
		select {
		case <-ctx.Done():
			s.log.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.runScheduledScan(ctx, contexts)
		}
	}
}

// runScheduledScan executes a full scan and stores the results.
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
		s.log.Error("scheduled scan: save failed", zap.Error(err))
		return
	}
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
