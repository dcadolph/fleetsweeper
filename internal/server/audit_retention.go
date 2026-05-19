package server

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// StartAuditRetention launches a goroutine that periodically deletes
// audit_log rows older than retain. retain <= 0 disables retention pruning
// (the table grows unboundedly until pruned externally). The ticker runs
// every hour but the first prune fires immediately so a fresh deployment
// with an existing database does not wait an hour.
func (s *Server) StartAuditRetention(ctx context.Context, retain time.Duration) {
	if retain <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		s.pruneAuditOnce(ctx, retain)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.pruneAuditOnce(ctx, retain)
			}
		}
	}()
}

// pruneAuditOnce performs a single retention pass.
func (s *Server) pruneAuditOnce(ctx context.Context, retain time.Duration) {
	cutoff := time.Now().Add(-retain).UTC()
	pruneCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	n, err := s.store.PruneAuditEntries(pruneCtx, cutoff)
	if err != nil {
		s.log.Warn("audit retention prune failed",
			zap.Time("cutoff", cutoff), zap.Error(err))
		return
	}
	if n > 0 {
		s.log.Info("audit retention pruned",
			zap.Int("rows", n), zap.Time("cutoff", cutoff))
	}
}
