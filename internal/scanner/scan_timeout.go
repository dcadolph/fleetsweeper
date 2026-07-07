package scanner

import (
	"context"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// DefaultScanTimeout bounds how long a single scanner may run against one
// cluster before it is abandoned, so a hung API call on one outlier cluster
// cannot stall the whole fleet sweep.
const DefaultScanTimeout = 60 * time.Second

// RunWithTimeout runs a scanner against a client under a deadline. A zero or
// negative timeout disables the deadline. A timeout surfaces as an ordinary
// scan error, which the caller records as degraded coverage rather than a clean
// result.
func RunWithTimeout(ctx context.Context, s Scanner, client *kube.Client, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		return s.Scan(ctx, client)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.Scan(ctx, client)
}
