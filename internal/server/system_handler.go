package server

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"go.uber.org/zap"
)

// systemResponse describes a snapshot of the running fleetsweeper process.
// The dashboard renders this at the top of the admin panel and external
// monitors poll it as a single "is everything healthy" check.
type systemResponse struct {
	// Version is the binary version (set via ldflags at build time).
	Version string `json:"version"`
	// Commit is the git commit hash baked into the binary.
	Commit string `json:"commit"`
	// BuildDate is when the binary was built.
	BuildDate string `json:"build_date"`
	// GoVersion is the Go runtime version.
	GoVersion string `json:"go_version"`
	// Uptime is how long the process has been running.
	Uptime string `json:"uptime"`
	// StartedAt is when the server initialised.
	StartedAt time.Time `json:"started_at"`
	// Features lists which optional features are active.
	Features systemFeatures `json:"features"`
	// Counters reports lifetime scan counts.
	Counters systemCounters `json:"counters"`
	// Storage describes the backend in use.
	Storage systemStorage `json:"storage"`
}

// systemFeatures enumerates optional features that can be toggled on/off.
type systemFeatures struct {
	// Insecure indicates --insecure auth bypass is in effect.
	Insecure bool `json:"insecure"`
	// Demo indicates the synthetic fleet is being served.
	Demo bool `json:"demo"`
	// SlackEnabled is true when a Slack webhook URL is configured.
	SlackEnabled bool `json:"slack_enabled"`
	// FleetDriftEmit is true when FleetDriftReport YAMLs are emitted.
	FleetDriftEmit bool `json:"fleetdrift_emit"`
	// PolicyReportEmit is true when wgpolicyk8s.io PolicyReports are emitted.
	PolicyReportEmit bool `json:"policyreport_emit"`
	// CostCorrelation is true when --cost-csv is set.
	CostCorrelation bool `json:"cost_correlation"`
	// InboundWebhooks is true when --webhook-secret is set.
	InboundWebhooks bool `json:"inbound_webhooks"`
	// OutboundWebhooks is true when --webhook-config is set.
	OutboundWebhooks bool `json:"outbound_webhooks"`
	// Sealing is true when --seal-key is set.
	Sealing bool `json:"sealing"`
}

// systemCounters reports lifetime scan statistics.
type systemCounters struct {
	// ScansOK is the count of successful scans since startup.
	ScansOK int64 `json:"scans_ok"`
	// ScansErr is the count of failed scans since startup.
	ScansErr int64 `json:"scans_err"`
	// LastScanDurationMS is the most recent scan duration.
	LastScanDurationMS int64 `json:"last_scan_duration_ms"`
}

// systemStorage describes the storage backend.
type systemStorage struct {
	// Driver is "sqlite" or "postgres".
	Driver string `json:"driver"`
	// Healthy reflects the most recent Ping result.
	Healthy bool `json:"healthy"`
}

// processStartTime is captured at package init so /admin/system can report
// uptime without threading a value through every constructor.
var processStartTime = time.Now()

// handleAdminSystem returns a single-glance summary of the running server.
func (s *Server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	scansOK, scansErr := s.scanCounts()
	resp := systemResponse{
		Version:   buildInfo.Version,
		Commit:    buildInfo.Commit,
		BuildDate: buildInfo.Date,
		GoVersion: runtime.Version(),
		Uptime:    time.Since(processStartTime).Round(time.Second).String(),
		StartedAt: processStartTime,
		Features: systemFeatures{
			Insecure:         s.insecure,
			Demo:             s.demo,
			SlackEnabled:     s.slackWebhookURL != "",
			FleetDriftEmit:   s.fleetDriftOutputDir != "",
			PolicyReportEmit: s.policyReportOutputDir != "",
			CostCorrelation:  s.costCSVPath != "",
			InboundWebhooks:  s.webhookSecret != "",
			OutboundWebhooks: s.webhookDispatcher != nil,
			Sealing:          s.sealKey != "",
		},
		Counters: systemCounters{
			ScansOK:            scansOK,
			ScansErr:           scansErr,
			LastScanDurationMS: s.lastScanDuration.Load() / int64(time.Millisecond),
		},
		Storage: systemStorage{
			Driver:  detectStoreDriver(s.store),
			Healthy: storeHealthy(r.Context(), s.store),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// detectStoreDriver returns a label identifying the active store backend.
// Implemented via a runtime type assertion against the concrete types in
// the store package so the Store interface itself stays minimal.
func detectStoreDriver(s any) string {
	switch s.(type) {
	case interface{ VacuumInto(context.Context, string) error }:
		return "sqlite"
	default:
		return "postgres"
	}
}

// storeHealthy probes the backend's Ping. Failures return false rather than
// erroring so the system endpoint always renders.
func storeHealthy(ctx context.Context, s any) bool {
	pinger, ok := s.(interface{ Ping(context.Context) error })
	if !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pinger.Ping(ctx) == nil
}

// buildInfo carries the binary version metadata. The cmd package overrides
// these at startup via SetBuildInfo; the package keeps a local copy so the
// server does not import cmd.
var buildInfo = struct {
	Version, Commit, Date string
}{Version: "dev", Commit: "unknown", Date: "unknown"}

// SetBuildInfo records build metadata so the /admin/system endpoint can
// report it. The cmd package calls this once during startup.
func SetBuildInfo(version, commit, date string) {
	if version != "" {
		buildInfo.Version = version
	}
	if commit != "" {
		buildInfo.Commit = commit
	}
	if date != "" {
		buildInfo.Date = date
	}
}

// _ keeps the zap import referenced for future logging additions.
var _ = zap.NewNop
