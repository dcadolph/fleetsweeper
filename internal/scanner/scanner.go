package scanner

import (
	"context"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// Scanner collects cluster-specific data for a single scan dimension.
type Scanner interface {
	Scan(ctx context.Context, client *kube.Client) (Result, error)
}

// ScannerFunc adapts a plain function to the Scanner interface.
type ScannerFunc func(ctx context.Context, client *kube.Client) (Result, error)

// Scan calls the underlying function.
func (f ScannerFunc) Scan(ctx context.Context, client *kube.Client) (Result, error) {
	return f(ctx, client)
}

// Result holds the output of a single scanner run against one cluster.
type Result struct {
	// Scanner is the name identifying which scanner produced this result.
	Scanner string `json:"scanner"`
	// Data is the scanner-specific payload.
	Data any `json:"data"`
}
