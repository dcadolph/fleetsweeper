package server

import (
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/policyreport"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// writePolicyReportIfConfigured emits wgpolicyk8s.io PolicyReport YAMLs for
// the given report when --policy-report-output is set. Failures are logged
// but never returned: notification or GitOps export failure must never break
// a scan.
func (s *Server) writePolicyReportIfConfigured(r *report.Report, scanID string) {
	if s.policyReportOutputDir == "" || r == nil {
		return
	}
	reports := policyreport.ReportsFor(r, scanID, s.policyReportNamespace)
	if err := policyreport.Write(reports, s.policyReportOutputDir); err != nil {
		s.log.Warn("policyreport: write failed",
			zap.String("dir", s.policyReportOutputDir),
			zap.Error(err),
		)
		return
	}
	s.log.Info("policyreport: wrote reports",
		zap.String("dir", s.policyReportOutputDir),
		zap.Int("count", len(reports)),
	)
}
