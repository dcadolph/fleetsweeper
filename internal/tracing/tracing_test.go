package tracing

import (
	"context"
	"testing"
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
