package logutil

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestWrapUnwrapLogger(t *testing.T) {
	t.Parallel()

	t.Run("wrapped logger is returned", func(t *testing.T) {
		t.Parallel()
		log := zaptest.NewLogger(t)
		ctx := WrapLogger(context.Background(), log)
		got := UnwrapLogger(ctx)
		if got != log {
			t.Error("expected the same logger instance")
		}
	})

	t.Run("no logger returns nop", func(t *testing.T) {
		t.Parallel()
		got := UnwrapLogger(context.Background())
		// Verify it works without panicking; nop loggers are not pointer-equal
		// so just check that a valid logger was returned.
		got.Info("should not panic")
	})
}
