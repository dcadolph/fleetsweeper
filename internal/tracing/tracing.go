// Package tracing wires up an OpenTelemetry tracer provider configured by the
// standard OTEL_EXPORTER_OTLP_ENDPOINT environment variable. When no exporter
// is configured the provider is a no-op, so instrumented code pays a single
// indirect-call cost and emits nothing. The intent is that Fleetsweeper's
// scan code can sprinkle spans freely without forcing every deployment to run
// a collector.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation library name used for spans emitted from
// Fleetsweeper packages. Backends and dashboards key off this string.
const TracerName = "github.com/dcadolph/fleetsweeper"

// shutdownTimeout caps how long we wait for the tracer provider to flush
// during process shutdown. Long enough for a healthy collector, short enough
// that a wedged collector cannot block a CLI exit indefinitely.
const shutdownTimeout = 5 * time.Second

// Init bootstraps OpenTelemetry tracer and meter providers for the process.
// It returns a shutdown function that the caller must invoke before exit so
// pending spans and metric points are flushed.
//
// Behavior:
//   - If OTEL_EXPORTER_OTLP_ENDPOINT (or the trace-specific variant) is
//     unset, the trace provider is the no-op SDK default.
//   - If OTEL_EXPORTER_OTLP_ENDPOINT (or the metrics-specific variant) is
//     unset, the meter provider is the no-op SDK default.
//   - When either endpoint is set, an OTLP-HTTP exporter is installed for
//     the corresponding signal with the appropriate processor.
//   - The W3C TraceContext propagator is installed unconditionally so
//     downstream callers can already participate in distributed traces.
//
// Version is the service version emitted as a resource attribute.
func Init(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	res := buildResource(ctx, serviceName, version)

	shutdownFns := []func(context.Context) error{}

	if hasTraceEndpoint() {
		tp, err := buildTracerProvider(ctx, res)
		if err != nil {
			return nil, fmt.Errorf("tracer provider: %w", err)
		}
		otel.SetTracerProvider(tp)
		shutdownFns = append(shutdownFns, func(c context.Context) error {
			return errors.Join(tp.ForceFlush(c), tp.Shutdown(c))
		})
	}

	if hasMetricEndpoint() {
		mp, err := buildMeterProvider(ctx, res)
		if err != nil {
			return nil, fmt.Errorf("meter provider: %w", err)
		}
		otel.SetMeterProvider(mp)
		shutdownFns = append(shutdownFns, func(c context.Context) error {
			return errors.Join(mp.ForceFlush(c), mp.Shutdown(c))
		})
	}

	return func(stopCtx context.Context) error {
		ctx, cancel := context.WithTimeout(stopCtx, shutdownTimeout)
		defer cancel()
		errs := make([]error, 0, len(shutdownFns))
		for _, fn := range shutdownFns {
			errs = append(errs, fn(ctx))
		}
		return errors.Join(errs...)
	}, nil
}

// buildResource composes the OTel resource attached to all exported signals.
// Resource detection failures fall back to a minimal resource so we still
// report something useful instead of refusing to export.
func buildResource(ctx context.Context, serviceName, version string) *sdkresource.Resource {
	res, err := sdkresource.New(ctx,
		sdkresource.WithFromEnv(),
		sdkresource.WithProcess(),
		sdkresource.WithTelemetrySDK(),
		sdkresource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
		),
	)
	if err != nil {
		return sdkresource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
		)
	}
	return res
}

// buildTracerProvider constructs the SDK tracer provider with an OTLP HTTP
// exporter and a batch span processor.
func buildTracerProvider(ctx context.Context, res *sdkresource.Resource) (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	), nil
}

// buildMeterProvider constructs the SDK meter provider with an OTLP HTTP
// metric exporter and a periodic reader.
func buildMeterProvider(ctx context.Context, res *sdkresource.Resource) (*sdkmetric.MeterProvider, error) {
	exporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("otlp metric exporter: %w", err)
	}
	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(30*time.Second),
	)
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	), nil
}

// hasEndpoint reports whether either trace or metrics OTLP endpoints are set.
// Kept for backwards compatibility with the original two-endpoint API.
func hasEndpoint() bool {
	return hasTraceEndpoint() || hasMetricEndpoint()
}

// hasTraceEndpoint reports whether a trace-OTLP endpoint env var is set.
func hasTraceEndpoint() bool {
	return envSet("OTEL_EXPORTER_OTLP_ENDPOINT") ||
		envSet("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

// hasMetricEndpoint reports whether a metric-OTLP endpoint env var is set.
func hasMetricEndpoint() bool {
	return envSet("OTEL_EXPORTER_OTLP_ENDPOINT") ||
		envSet("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
}

// envSet reports whether the named env var is set to a non-empty value.
func envSet(name string) bool {
	v, ok := os.LookupEnv(name)
	return ok && v != ""
}

// Tracer returns the package-scoped tracer used to start spans from anywhere
// in Fleetsweeper. Safe to call before Init: the global provider falls back
// to a no-op until Init installs one.
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// Meter returns the package-scoped meter used to register metric instruments
// from anywhere in Fleetsweeper. Safe to call before Init: the global meter
// provider falls back to a no-op until Init installs one.
func Meter() metric.Meter {
	return otel.Meter(TracerName)
}
