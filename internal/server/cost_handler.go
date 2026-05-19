package server

import (
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// handleGetCost returns a cost-correlation Analysis for the most recent
// scan, joined against the operator-supplied CSV at --cost-csv. In demo
// mode with no CSV configured, a built-in synthetic CSV is used so the
// dashboard renders the cost panel without operator setup.
func (s *Server) handleGetCost(w http.ResponseWriter, r *http.Request) {
	var costs cost.Map
	switch {
	case s.costCSVPath != "":
		loaded, err := cost.LoadCSV(s.costCSVPath)
		if err != nil {
			s.log.Warn("cost: load csv", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "load cost csv failed")
			return
		}
		costs = loaded
	case s.demo:
		costs = demoCostMap()
	default:
		writeJSON(w, http.StatusOK, cost.Analysis{Currency: "USD"})
		return
	}

	var rpt *report.Report
	scans, err := s.store.ListScans(r.Context(), 1)
	if err == nil && len(scans) > 0 {
		results, err := s.store.GetScanResults(r.Context(), scans[0].ID)
		if err == nil {
			rpt = report.Build(scans[0].Clusters, results)
		}
	}
	if rpt == nil && s.demo {
		rpt = demoReport()
	}

	analysis := cost.Correlate(rpt, costs)
	writeJSON(w, http.StatusOK, analysis)
}

// demoCostCSV is the synthetic cost spreadsheet shipped to the demo
// dashboard so the cost panel always has data without any operator setup.
// Numbers are illustrative; the shape is what matters.
const demoCostCSV = `cluster,period,cost_usd
prod-us-east-1,2026-05,2400.50
prod-us-west-2,2026-05,2180.00
prod-eu-central-1,2026-05,1980.00
prod-europe-west2,2026-05,1820.00
prod-japaneast,2026-05,1450.00
prod-ap-south-1,2026-05,890.00
staging-ap-southeast-1,2026-05,420.00
staging-ap-northeast-2,2026-05,380.00
dev-us-central1,2026-05,120.00
dev-canadacentral,2026-05,95.00
dev-eu-north-1,2026-05,110.00
store-nyc-42,2026-05,180.25
store-london-soho,2026-05,165.00
store-sydney-cbd,2026-05,150.00
store-paris-12,2026-05,140.00
store-dubai-mall,2026-05,135.00
store-mexico-city,2026-05,120.00
edge-buenos-aires,2026-05,80.00
edge-lagos,2026-05,75.00
edge-johannesburg,2026-05,90.00
warehouse-sao-paulo,2026-05,210.00
factory-osaka,2026-05,310.00
dev-australiasoutheast,2026-05,85.00
dev-southamerica-east1,2026-05,75.00
store-vancouver,2026-05,130.00
store-honolulu,2026-05,140.00
`

// demoCostMap parses the embedded demo CSV. Errors here are programmer
// errors (the string is a constant) so an empty Map is returned rather
// than surfacing the parse failure to the operator.
func demoCostMap() cost.Map {
	m, err := cost.ParseCSV(strings.NewReader(demoCostCSV))
	if err != nil {
		return cost.Map{}
	}
	return m
}
