package server

import (
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/fleetdrift"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// writeFleetDriftIfConfigured emits FleetDriftReport YAML files for the given
// report when --fleetdrift-output is set. Failures are logged but never
// returned: notification or GitOps export failure must never break a scan.
func (s *Server) writeFleetDriftIfConfigured(r *report.Report, scanID string) {
	if s.fleetDriftOutputDir == "" || r == nil {
		return
	}
	reports := fleetdrift.ReportsFor(r, scanID, "")
	if err := fleetdrift.Write(reports, s.fleetDriftOutputDir); err != nil {
		s.log.Warn("fleetdrift: write failed",
			zap.String("dir", s.fleetDriftOutputDir),
			zap.Error(err),
		)
		return
	}
	s.log.Info("fleetdrift: wrote reports",
		zap.String("dir", s.fleetDriftOutputDir),
		zap.Int("count", len(reports)),
	)
}
