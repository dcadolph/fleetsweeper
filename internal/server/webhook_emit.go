package server

import (
	"context"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/webhooks"
)

// zapWebhookLogger adapts a *zap.Logger to the webhooks.Logger interface
// without leaking zap into the webhooks package.
type zapWebhookLogger struct {
	log *zap.Logger
}

// Warnw implements webhooks.Logger.
func (z zapWebhookLogger) Warnw(msg string, kv ...any) {
	z.log.Sugar().Warnw(msg, kv...)
}

// Infow implements webhooks.Logger.
func (z zapWebhookLogger) Infow(msg string, kv ...any) {
	z.log.Sugar().Infow(msg, kv...)
}

// dispatchWebhooksIfConfigured forwards the report's findings to every
// configured outbound subscriber. Filters out acked findings using the
// same path the Slack notifier uses so a single ack quiets every channel.
func (s *Server) dispatchWebhooksIfConfigured(ctx context.Context, r *report.Report) {
	if s.webhookDispatcher == nil || r == nil {
		return
	}
	findings := r.Findings
	if s.store != nil {
		findings = s.filterAckedFindings(ctx, findings)
	}
	s.webhookDispatcher.Dispatch(ctx, findings)
}

// webhookConfigPathOrEmpty returns the configured webhook config path, used
// by the integrations handler for status reporting. Indirected through this
// helper so the field can change name without touching the handler.
func (s *Server) webhookConfigPathOrEmpty() string {
	return s.webhookConfigPath
}

// setupWebhooks loads the webhook config and constructs the dispatcher. A
// missing path is not an error; a malformed config is logged and ignored so
// startup never blocks on a subscriber misconfiguration.
func (s *Server) setupWebhooks(path string) {
	s.webhookConfigPath = path
	if path == "" {
		return
	}
	cfg, err := webhooks.LoadConfig(path)
	if err != nil {
		s.log.Warn("webhooks: load failed", zap.String("path", path), zap.Error(err))
		return
	}
	s.webhookDispatcher = webhooks.NewDispatcher(cfg, zapWebhookLogger{log: s.log})
	s.log.Info("webhooks: configured",
		zap.String("path", path),
		zap.Int("subscribers", len(cfg.Webhooks)))
}
