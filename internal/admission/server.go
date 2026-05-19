package admission

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ServerConfig configures the admission HTTP server.
type ServerConfig struct {
	// Addr is the listen address (typically ":8443").
	Addr string
	// CertPath is an optional path to a PEM-encoded TLS certificate. When
	// empty a fresh self-signed cert is generated.
	CertPath string
	// KeyPath is the matching private key path.
	KeyPath string
	// DNSNames are the SANs to include on a generated certificate. The
	// ValidatingWebhookConfiguration must address the service via one of
	// these names.
	DNSNames []string
	// Handler is the admission handler.
	Handler *Handler
	// Log is the structured logger.
	Log *zap.Logger
}

// Server runs the admission webhook HTTP server. Lifecycle mirrors the
// main fleetsweeper server: ListenAndServeTLS until the supplied context
// cancels, then Shutdown.
type Server struct {
	cfg  ServerConfig
	cert tls.Certificate
	caPEM []byte
	httpServer *http.Server
}

// NewServer prepares the admission server's TLS material and HTTP wiring.
// Call Run to start serving.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("admission server: handler required")
	}
	if cfg.Log == nil {
		return nil, errors.New("admission server: log required")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	cert, caPEM, err := LoadOrGenerateCertificate(cfg.CertPath, cfg.KeyPath, cfg.DNSNames)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/admission/validate", cfg.Handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return &Server{
		cfg:   cfg,
		cert:  cert,
		caPEM: caPEM,
		httpServer: &http.Server{
			Addr:    cfg.Addr,
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}, nil
}

// CABundle returns the PEM-encoded CA bundle the apiserver should use to
// verify the webhook. Callers patch this into the
// ValidatingWebhookConfiguration's webhook.clientConfig.caBundle.
func (s *Server) CABundle() []byte { return s.caPEM }

// Run serves the admission endpoint until ctx is cancelled. Returns nil on
// a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.cfg.Log.Info("admission server listening",
		zap.String("addr", s.cfg.Addr),
		zap.Strings("dns_names", s.cfg.DNSNames),
	)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
