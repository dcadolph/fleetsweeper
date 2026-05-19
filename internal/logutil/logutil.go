// Package logutil ties a structured zap logger to a context.Context so handlers thread the same logger without explicit arguments.
package logutil

import (
	"context"

	"go.uber.org/zap"
)

type contextKey struct{}

// WrapLogger stores a zap logger in the context.
func WrapLogger(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, log)
}

// UnwrapLogger retrieves the zap logger from the context. Returns a no-op
// logger when none is present.
func UnwrapLogger(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(contextKey{}).(*zap.Logger); ok {
		return l
	}
	return zap.NewNop()
}

// ContextField returns a zap field for a kubeconfig context name.
func ContextField(name string) zap.Field {
	return zap.String("context", name)
}

// ErrorField returns a zap field for an error value.
func ErrorField(err error) zap.Field {
	return zap.Error(err)
}
