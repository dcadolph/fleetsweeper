package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// writeDemoClusterDetail synthesizes a per-cluster detail payload from
// demoReport so the cluster-detail page works end-to-end in demo mode.
func (s *Server) writeDemoClusterDetail(w http.ResponseWriter, cluster string) {
	rpt := demoReport()
	var health *report.ClusterHealth
	for i := range rpt.ClusterHealths {
		if rpt.ClusterHealths[i].Name == cluster {
			health = &rpt.ClusterHealths[i]
			break
		}
	}
	if health == nil {
		writeError(w, http.StatusNotFound, "cluster not found in demo fleet")
		return
	}
	var findings []report.Finding
	for _, f := range rpt.Findings {
		if f.Cluster == cluster || f.Cluster == "fleet" {
			findings = append(findings, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":      cluster,
		"scan_id":      demoScanID,
		"scan_time":    demoTimestamp(),
		"health":       health,
		"findings":     findings,
		"scanner_data": map[string]any{},
	})
}

// errorResponse is a JSON error body.
type errorResponse struct {
	// Error is a sanitized error message safe to return to clients.
	Error string `json:"error"`
	// Code is the HTTP status code.
	Code int `json:"code"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"marshal failed","code":500}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeError writes a JSON error response with a sanitized message.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg, Code: status})
}

// safeMessage strips potentially sensitive substrings (filesystem paths, home
// directories) from an error message before returning it to clients.
func safeMessage(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	msg := err.Error()
	if strings.Contains(msg, "/") || strings.Contains(msg, "\\") {
		return fallback
	}
	return msg
}

// handleListScans returns recent scans.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.log.Error("list scans", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return
	}
	if len(scans) == 0 && s.demo {
		writeJSON(w, http.StatusOK, []store.ScanRecord{demoScanRecord()})
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// handleGetScan returns a scan record by ID.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.demo && id == demoScanID {
		rec := demoScanRecord()
		writeJSON(w, http.StatusOK, rec)
		return
	}
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		s.log.Info("get scan", zap.String("id", id), zap.Error(err))
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// handleGetScanReport rebuilds and returns the full report for a scan.
func (s *Server) handleGetScanReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	if s.demo && id == demoScanID {
		writeJSON(w, http.StatusOK, demoReport())
		return
	}

	scan, err := s.store.GetScan(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}

	results, err := s.store.GetScanResults(ctx, id)
	if err != nil {
		s.log.Error("get scan results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	rpt := report.Build(scan.Clusters, results)

	if len(r.URL.Query()["tag"]) > 0 {
		tagAllows, err := s.parseTagFilter(ctx, r)
		if err != nil {
			s.log.Warn("tag filter", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "load tag filter failed")
			return
		}
		filtered := rpt.Findings[:0]
		for _, f := range rpt.Findings {
			// Fleet-wide findings (cluster=="" or "fleet") are kept
			// regardless of tags because they aren't owned by any one
			// cluster; tag filtering applies only to per-cluster rows.
			if f.Cluster == "" || f.Cluster == "fleet" || tagAllows(f.Cluster) {
				filtered = append(filtered, f)
			}
		}
		rpt.Findings = filtered
	}

	writeJSON(w, http.StatusOK, rpt)
}

// triggerScanRequest is the JSON body for POST /api/scans.
type triggerScanRequest struct {
	// Contexts is the list of kubeconfig contexts to scan.
	Contexts []string `json:"contexts"`
	// AllContexts scans all available contexts when true.
	AllContexts bool `json:"all_contexts"`
	// Group scans only clusters in this group.
	Group string `json:"group"`
}

// triggerScanResponse is the JSON response for POST /api/scans.
type triggerScanResponse struct {
	// ScanID is the pre-allocated identifier of the triggered scan.
	ScanID string `json:"scan_id"`
	// Status is "running"; clients should poll GET /api/scans/{id} for completion.
	Status string `json:"status"`
}

// handleTriggerScan starts a scan asynchronously under the server-scoped
// context. The scan ID is generated synchronously and returned immediately so
// clients can correlate the eventual record. Concurrent triggers receive 429.
func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	var req triggerScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	contexts, err := s.resolveContexts(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, safeMessage(err, "invalid contexts"))
		return
	}

	if len(contexts) == 0 {
		writeError(w, http.StatusBadRequest, "no contexts specified")
		return
	}

	actor := actorFromContext(r.Context())
	contexts = actor.FilterClusters(contexts, s.groupLookup(r.Context()))
	if len(contexts) == 0 {
		writeError(w, http.StatusForbidden, "no contexts in actor scope")
		return
	}

	if !s.scanBusy.CompareAndSwap(false, true) {
		writeError(w, http.StatusTooManyRequests, "scan in progress; retry later")
		return
	}

	go func(contexts []string) {
		defer s.scanBusy.Store(false)
		s.scanMu.Lock()
		defer s.scanMu.Unlock()

		ctx := s.ctx
		s.log.Info("triggered scan starting", zap.Int("contexts", len(contexts)))
		started := time.Now()

		clients := kube.ConnectAll(ctx, s.kubeconfigPath, contexts, s.workers)
		if len(clients) == 0 {
			s.scansErr.Add(1)
			s.log.Warn("triggered scan: no clusters reachable")
			return
		}

		results := runScanners(ctx, clients, s.registry.All(), s.workers, s.log)
		clusterNames := make([]string, len(clients))
		for i, c := range clients {
			clusterNames[i] = c.Context
		}

		scanID, err := s.store.SaveScan(ctx, clusterNames, results)
		if err != nil {
			s.scansErr.Add(1)
			s.recordScanCompletion(false)
			s.log.Error("triggered scan: save failed", zap.Error(err))
			return
		}
		s.scansOK.Add(1)
		s.recordScanDuration(time.Since(started))
		s.recordScanCompletion(true)
		s.log.Info("triggered scan complete", zap.String("scan_id", scanID))
		rpt := report.Build(clusterNames, results)
		s.notifySlackForReport(ctx, rpt)
		s.writeFleetDriftIfConfigured(rpt, scanID)
		s.writePolicyReportIfConfigured(rpt, scanID)
		s.dispatchWebhooksIfConfigured(ctx, rpt)
		s.PublishEvent(EventScanComplete, map[string]any{
			"scan_id":  scanID,
			"clusters": len(clusterNames),
			"score":    rpt.FleetScore.Score,
			"grade":    rpt.FleetScore.Grade,
		})
	}(contexts)

	writeJSON(w, http.StatusAccepted, triggerScanResponse{Status: "running"})
}

// resolveContexts determines which kubeconfig contexts to scan for a trigger request.
func (s *Server) resolveContexts(ctx context.Context, req triggerScanRequest) ([]string, error) {
	if req.Group != "" {
		g, err := s.store.GetGroup(ctx, req.Group)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", req.Group, err)
		}
		return g.Clusters, nil
	}
	if req.AllContexts {
		return kube.AvailableContexts(s.kubeconfigPath)
	}
	return req.Contexts, nil
}

// handleListClusters returns all known clusters with their tag maps
// inlined so the dashboard can render tag chips without a follow-up
// /api/tags fetch.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	clusters, err := s.store.ListClusters(r.Context())
	if err != nil {
		s.log.Error("list clusters", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list clusters failed")
		return
	}
	if len(clusters) == 0 && s.demo {
		rec := demoScanRecord()
		out := make([]store.ClusterRecord, 0, len(rec.Clusters))
		for _, c := range rec.Clusters {
			out = append(out, store.ClusterRecord{Name: c, FirstSeen: rec.Timestamp, LastSeen: rec.Timestamp})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	tags, err := s.store.ListClusterTags(r.Context())
	if err != nil {
		s.log.Warn("list cluster tags", zap.Error(err))
	} else {
		for i := range clusters {
			if t, ok := tags[clusters[i].Name]; ok {
				clusters[i].Tags = t
			}
		}
	}
	writeJSON(w, http.StatusOK, clusters)
}

// handleGetClusterDetail returns full scanner data for a cluster from the
// latest scan, plus its health summary and relevant findings.
func (s *Server) handleGetClusterDetail(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	ctx := r.Context()

	scans, err := s.store.ListScans(ctx, 1)
	if err != nil || len(scans) == 0 {
		if s.demo {
			s.writeDemoClusterDetail(w, cluster)
			return
		}
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	results, err := s.store.GetScanResults(ctx, scans[0].ID)
	if err != nil {
		s.log.Error("cluster detail: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	clusterData, ok := results[cluster]
	if !ok {
		writeError(w, http.StatusNotFound, "cluster not found in latest scan")
		return
	}

	rpt := report.Build(scans[0].Clusters, results)

	var clusterHealth *report.ClusterHealth
	for i := range rpt.ClusterHealths {
		if rpt.ClusterHealths[i].Name == cluster {
			clusterHealth = &rpt.ClusterHealths[i]
			break
		}
	}

	var clusterFindings []report.Finding
	for _, f := range rpt.Findings {
		if f.Cluster == cluster || f.Cluster == "fleet" {
			clusterFindings = append(clusterFindings, f)
		}
	}

	scannerData := make(map[string]any, len(clusterData))
	for name, result := range clusterData {
		scannerData[name] = result.Data
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":      cluster,
		"scan_id":      scans[0].ID,
		"scan_time":    scans[0].Timestamp,
		"health":       clusterHealth,
		"findings":     clusterFindings,
		"scanner_data": scannerData,
	})
}

// handleListGroups returns all groups.
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.log.Error("list groups", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list groups failed")
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

// createGroupRequest is the JSON body for POST /api/groups.
type createGroupRequest struct {
	// Name is the group name.
	Name string `json:"name"`
	// Clusters is the list of cluster names.
	Clusters []string `json:"clusters"`
}

// handleCreateGroup creates a new group.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := s.store.SaveGroup(r.Context(), req.Name, req.Clusters); err != nil {
		s.log.Error("save group", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "save group failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name})
}

// handleDeleteGroup deletes a group.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteGroup(r.Context(), name); err != nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetTrends returns fleet-wide trend analysis from the last N scans.
func (s *Server) handleGetTrends(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if v := r.URL.Query().Get("scans"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.log.Error("list scans for trends", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return
	}
	if len(scans) < 2 {
		if s.demo {
			trends := demoFleetTrends()
			writeJSON(w, http.StatusOK, map[string]any{
				"fleet_trends": trends,
				"findings":     report.GenerateTrendFindings(nil, trends),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "need at least 2 scans for trends"})
		return
	}

	scanMetas := make([]report.ScanMeta, len(scans))
	fleetResults := make(map[string]map[string]map[string]any, len(scans))

	for i, scan := range scans {
		scanMetas[i] = report.ScanMeta{ID: scan.ID, Timestamp: scan.Timestamp}
		raw, err := s.store.GetScanResults(r.Context(), scan.ID)
		if err != nil {
			s.log.Warn("trends: skipping scan", zap.String("id", scan.ID), zap.Error(err))
			continue
		}
		clusterData := make(map[string]map[string]any)
		for cluster, scanners := range raw {
			scannerFields := make(map[string]any)
			for scannerName, result := range scanners {
				b, err := json.Marshal(result.Data)
				if err != nil {
					continue
				}
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					continue
				}
				scannerFields[scannerName] = m
			}
			clusterData[cluster] = scannerFields
		}
		fleetResults[scan.ID] = clusterData
	}

	trends := report.ComputeFleetTrends(scanMetas, fleetResults)
	findings := report.GenerateTrendFindings(nil, trends)
	writeJSON(w, http.StatusOK, map[string]any{
		"fleet_trends": trends,
		"findings":     findings,
	})
}

// handleGetClusterTrends returns trends for a specific cluster.
func (s *Server) handleGetClusterTrends(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	limit := 10
	if v := r.URL.Query().Get("scans"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.log.Error("list scans for cluster trends", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return
	}

	scanMetas := make([]report.ScanMeta, len(scans))
	clusterResults := make(map[string]map[string]map[string]any, len(scans))

	for i, scan := range scans {
		scanMetas[i] = report.ScanMeta{ID: scan.ID, Timestamp: scan.Timestamp}
		raw, err := s.store.GetScanResults(r.Context(), scan.ID)
		if err != nil {
			s.log.Warn("cluster trends: skipping scan", zap.String("id", scan.ID), zap.Error(err))
			continue
		}
		if clusterScanners, ok := raw[cluster]; ok {
			scannerData := make(map[string]map[string]any)
			for scannerName, result := range clusterScanners {
				b, err := json.Marshal(result.Data)
				if err != nil {
					continue
				}
				var m map[string]any
				if err := json.Unmarshal(b, &m); err != nil {
					continue
				}
				scannerData[scannerName] = m
			}
			clusterResults[scan.ID] = scannerData
		}
	}

	trends := report.ComputeClusterTrends(cluster, scanMetas, clusterResults)
	findings := report.GenerateTrendFindings(trends, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":        cluster,
		"cluster_trends": trends,
		"findings":       findings,
	})
}

// handleGetOutliers runs outlier detection on the most recent scan.
func (s *Server) handleGetOutliers(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context(), 1)
	if err != nil || len(scans) == 0 {
		if s.demo {
			rpt := demoReport()
			writeJSON(w, http.StatusOK, map[string]any{
				"scan_id":  demoScanID,
				"outliers": demoOutliers(),
				"findings": rpt.Findings,
			})
			return
		}
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	latest := scans[0]
	results, err := s.store.GetScanResults(r.Context(), latest.ID)
	if err != nil {
		s.log.Error("outliers: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	threshold := 3.5
	if v := r.URL.Query().Get("threshold"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			threshold = f
		}
	}

	rpt := report.Build(latest.Clusters, results, report.BuildOptions{OutlierThreshold: threshold})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":  latest.ID,
		"outliers": rpt.Outliers,
		"findings": rpt.Findings,
	})
}

// handleGetCapacity returns capacity analysis with correlated signals.
func (s *Server) handleGetCapacity(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context(), 1)
	if err != nil || len(scans) == 0 {
		if s.demo {
			writeJSON(w, http.StatusOK, map[string]any{
				"scan_id":  demoScanID,
				"capacity": demoReport().Capacity,
			})
			return
		}
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	results, err := s.store.GetScanResults(r.Context(), scans[0].ID)
	if err != nil {
		s.log.Error("capacity: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	groups, _ := s.store.ListGroups(r.Context())
	groupMap := make(map[string][]string, len(groups))
	for _, g := range groups {
		groupMap[g.Name] = g.Clusters
	}

	rpt := report.Build(scans[0].Clusters, results, report.BuildOptions{Groups: groupMap})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":  scans[0].ID,
		"capacity": rpt.Capacity,
	})
}

// contextInfo describes a kubeconfig context the UI can offer to scan.
type contextInfo struct {
	// Name is the kubeconfig context name.
	Name string `json:"name"`
	// Scanned is true when this context already appears in stored scans.
	Scanned bool `json:"scanned"`
}

// handleListContexts returns the kubeconfig contexts available to the server,
// each annotated with whether the cluster has already been scanned. The UI
// uses this to power the "Add cluster" page so operators can grow the fleet
// without leaving the dashboard. In demo mode the synthetic fleet's contexts
// are returned so the page is not empty on first paint.
func (s *Server) handleListContexts(w http.ResponseWriter, r *http.Request) {
	if s.demo {
		seen := make(map[string]bool, len(demoPoints()))
		out := make([]contextInfo, 0, len(demoPoints()))
		for _, p := range demoPoints() {
			if seen[p.Cluster] {
				continue
			}
			seen[p.Cluster] = true
			out = append(out, contextInfo{Name: p.Cluster, Scanned: true})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	contexts, err := kube.AvailableContexts(s.kubeconfigPath)
	if err != nil {
		s.log.Warn("list contexts", zap.Error(err))
		writeJSON(w, http.StatusOK, []contextInfo{})
		return
	}
	known, _ := s.store.ListClusters(r.Context())
	knownSet := make(map[string]struct{}, len(known))
	for _, c := range known {
		knownSet[c.Name] = struct{}{}
	}
	out := make([]contextInfo, 0, len(contexts))
	for _, c := range contexts {
		_, scanned := knownSet[c]
		out = append(out, contextInfo{Name: c, Scanned: scanned})
	}
	writeJSON(w, http.StatusOK, out)
}

// errFault is a sentinel error returned by handlers that have already
// logged the underlying cause. Kept for future use by callers that need
// to differentiate transport errors from policy errors. Not currently
// emitted directly.
var errFault = errors.New("internal fault")

var _ = errFault
