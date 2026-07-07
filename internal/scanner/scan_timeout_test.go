package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// TestRunWithTimeout verifies a hung scanner is abandoned at the deadline and a
// zero timeout runs the scanner unbounded.
func TestRunWithTimeout(t *testing.T) {
	t.Parallel()

	blocking := ScannerFunc(func(ctx context.Context, _ *kube.Client) (Result, error) {
		<-ctx.Done()
		return Result{}, ctx.Err()
	})

	start := time.Now()
	_, err := RunWithTimeout(context.Background(), blocking, nil, 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Error("timeout did not fire promptly")
	}

	fast := ScannerFunc(func(_ context.Context, _ *kube.Client) (Result, error) {
		return Result{Scanner: "x"}, nil
	})
	if _, err := RunWithTimeout(context.Background(), fast, nil, 0); err != nil {
		t.Errorf("zero timeout should not error: %v", err)
	}
}
