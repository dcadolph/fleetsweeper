package tracing

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestInit_NoEndpoint_IsNoOp confirms that without an OTLP endpoint the
// returned shutdown function is a safe no-op. Cannot be t.Parallel because
// t.Setenv panics in parallel tests.
func TestInit_NoEndpoint_IsNoOp(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := Init(context.Background(), "fleetsweeper-test", "0.0.0")
	if err != nil {
		t.Fatalf("Init: unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatalf("Init returned nil shutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestTracer_AlwaysSafe confirms Tracer() never returns nil and spans can be
// started and ended without panic, even with no exporter configured.
func TestTracer_AlwaysSafe(t *testing.T) {
	t.Parallel()
	tr := Tracer()
	if tr == nil {
		t.Fatalf("Tracer() returned nil")
	}
	_, span := tr.Start(context.Background(), "test-span")
	span.End()
}

// TestInitEndpoints exercises Init across the endpoint permutations: no
// exporter (pure no-op), trace-only, metric-only, and the generic endpoint
// that installs both providers. Each case must construct without error and
// yield a shutdown function that runs to completion without panicking. Cannot
// use t.Parallel because t.Setenv forbids it.
func TestInitEndpoints(t *testing.T) {
	tests := []struct {
		Env             map[string]string
		Name            string
		Want            error
		WantShutdownNil bool
	}{{ // Test 0: No endpoints, the provider is a no-op and shutdown is a clean nil.
		Name: "no endpoints",
		Env: map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":         "",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "",
		},
		WantShutdownNil: true,
	}, { // Test 1: Trace-specific endpoint installs only a tracer provider.
		Name: "trace only",
		Env: map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":         "",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "http://127.0.0.1:4318/v1/traces",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "",
		},
	}, { // Test 2: Metric-specific endpoint installs only a meter provider.
		Name: "metric only",
		Env: map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":         "",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:4318/v1/metrics",
		},
	}, { // Test 3: Generic endpoint installs both signals.
		Name: "generic both",
		Env: map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":         "http://127.0.0.1:4318",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "",
		},
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			for k, v := range test.Env {
				t.Setenv(k, v)
			}
			shutdown, err := Init(context.Background(), "fleetsweeper-test", "1.2.3")
			if !errors.Is(err, test.Want) {
				t.Fatalf("Init error: want %v, got %v", test.Want, err)
			}
			if shutdown == nil {
				t.Fatalf("Init returned nil shutdown")
			}
			// Bound the shutdown so an unreachable collector cannot stall the
			// test; without emitted spans it returns promptly regardless.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if gotErr := shutdown(ctx); test.WantShutdownNil && gotErr != nil {
				t.Errorf("shutdown: want nil, got %v", gotErr)
			}
		})
	}
}

// TestMeterAlwaysSafe confirms Meter() never returns nil and can register an
// instrument even with no exporter configured.
func TestMeterAlwaysSafe(t *testing.T) {
	t.Parallel()
	m := Meter()
	if m == nil {
		t.Fatal("Meter() returned nil")
	}
	if _, err := m.Int64Counter("fleetsweeper.test.counter"); err != nil {
		t.Errorf("Int64Counter: %v", err)
	}
}

// TestHasEndpoint covers the env-var detection branches.
func TestHasEndpoint(t *testing.T) {
	tests := []struct {
		Name string
		Env  map[string]string
		Want bool
	}{
		{"neither set", map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":        "",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "",
		}, false},
		{"generic set", map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":        "http://otel:4318",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "",
		}, true},
		{"traces-specific set", map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT":        "",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://otel:4318/v1/traces",
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			for k, v := range tc.Env {
				t.Setenv(k, v)
			}
			if got := hasEndpoint(); got != tc.Want {
				t.Errorf("hasEndpoint: want %v, got %v", tc.Want, got)
			}
		})
	}
}
