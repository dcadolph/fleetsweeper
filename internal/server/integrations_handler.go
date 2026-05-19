package server

import (
	"net/http"
	"os"
)

// integrationStatus describes a single configured integration. Keeping
// status to a small finite vocabulary ("configured", "off", "demo") makes the
// UI easy and avoids leaking misleading "healthy" claims about external
// systems Fleetsweeper has not actually pinged.
type integrationStatus struct {
	// Name is the human-readable label.
	Name string `json:"name"`
	// Status is one of "configured", "off", or "demo".
	Status string `json:"status"`
	// Hint is a short string the UI shows under the integration row.
	Hint string `json:"hint,omitempty"`
}

// integrationsResponse is the wire shape of GET /api/integrations.
type integrationsResponse struct {
	// Items is the per-integration status list.
	Items []integrationStatus `json:"items"`
}

// handleGetIntegrations returns which integrations are wired up so the
// dashboard can render a "Plumbing" panel without parsing the operator's
// command line. Status is derived from server configuration only; we do not
// actively ping Slack or OTel from this handler, because that would conflate
// "configured" with "reachable" and lead to false-positive alerts.
func (s *Server) handleGetIntegrations(w http.ResponseWriter, _ *http.Request) {
	items := []integrationStatus{
		{Name: "Prometheus /metrics", Status: configuredOr("configured", "off",
			s.adminServer != nil)},
		{Name: "OpenTelemetry traces", Status: configuredOr("configured", "off",
			os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
				os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""),
			Hint: "Set OTEL_EXPORTER_OTLP_ENDPOINT to enable"},
		{Name: "OpenTelemetry metrics", Status: configuredOr("configured", "off",
			os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
				os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != "")},
		{Name: "Slack webhook", Status: configuredOr("configured", "off",
			s.slackWebhookURL != ""),
			Hint: "Pass --slack-webhook-url to enable"},
		{Name: "FleetDriftReport export", Status: configuredOr("configured", "off",
			s.fleetDriftOutputDir != ""),
			Hint: "Pass --fleetdrift-output <dir> to enable"},
		{Name: "PolicyReport export", Status: configuredOr("configured", "off",
			s.policyReportOutputDir != ""),
			Hint: "Pass --policy-report-output <dir> to enable"},
		{Name: "Cost correlation", Status: configuredOr("configured", "off",
			s.costCSVPath != ""),
			Hint: "Pass --cost-csv <path> to enable"},
		{Name: "Demo mode", Status: configuredOr("demo", "off", s.demo)},
		{Name: "Bearer auth", Status: configuredOr("configured", "off (insecure)",
			s.authToken != "")},
	}
	writeJSON(w, http.StatusOK, integrationsResponse{Items: items})
}

// configuredOr returns either the on string or the off string based on b.
func configuredOr(on, off string, b bool) string {
	if b {
		return on
	}
	return off
}
