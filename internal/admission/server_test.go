package admission

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// testHandler returns a minimal handler suitable for wiring a server.
func testHandler() *Handler {
	return &Handler{
		Provider: fakeProvider{b: sufficientBaseline},
		Checks:   DefaultChecks(),
		Mode:     ModeAdvisory,
		Log:      zap.NewNop(),
	}
}

// TestNewServerValidation verifies the constructor rejects configs missing a
// handler or logger.
func TestNewServerValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Cfg     ServerConfig
		WantErr bool
	}{
		{Cfg: ServerConfig{Log: zap.NewNop()}, WantErr: true},                          // Test 0: No handler.
		{Cfg: ServerConfig{Handler: testHandler()}, WantErr: true},                     // Test 1: No logger.
		{Cfg: ServerConfig{Handler: testHandler(), Log: zap.NewNop()}, WantErr: false}, // Test 2: Valid.
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			_, err := NewServer(test.Cfg)
			if (err != nil) != test.WantErr {
				t.Errorf("test %d: err = %v, wantErr = %v", testNum, err, test.WantErr)
			}
		})
	}
}

// TestNewServerGenerated verifies a config without cert paths generates TLS
// material, defaults the listen address, and exposes a parseable CA bundle.
func TestNewServerGenerated(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(ServerConfig{
		Handler:  testHandler(),
		Log:      zap.NewNop(),
		DNSNames: []string{"fleetsweeper.fleet.svc"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.cfg.Addr != ":8443" {
		t.Errorf("Addr = %q, want :8443", srv.cfg.Addr)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(srv.CABundle()) {
		t.Error("CABundle did not yield a parseable certificate")
	}
}

// TestNewServerFileCertError verifies the constructor surfaces a cert-source
// failure when the configured keypair paths do not exist.
func TestNewServerFileCertError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := NewServer(ServerConfig{
		Handler:  testHandler(),
		Log:      zap.NewNop(),
		CertPath: filepath.Join(dir, "missing.crt"),
		KeyPath:  filepath.Join(dir, "missing.key"),
	})
	if err == nil {
		t.Fatal("expected an error for missing cert files")
	}
}

// TestServerRunShutdown verifies Run serves until the context cancels and then
// returns nil after a clean shutdown.
func TestServerRunShutdown(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(ServerConfig{
		Handler:  testHandler(),
		Log:      zap.NewNop(),
		Addr:     "127.0.0.1:0",
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Give the listener a moment to bind before triggering shutdown.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestServerRunListenError verifies Run returns the listen error when the
// address cannot be bound.
func TestServerRunListenError(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(ServerConfig{
		Handler:  testHandler(),
		Log:      zap.NewNop(),
		Addr:     "bad-address-without-a-port",
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	runErr := srv.Run(context.Background())
	if runErr == nil {
		t.Fatal("expected a listen error, got nil")
	}
}
