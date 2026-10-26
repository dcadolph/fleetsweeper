package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

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

// maxJSONBody is the largest JSON request body an API handler accepts.
const maxJSONBody = 1 << 20

// maxScanWindow caps how many scans one list or trend request may load.
const maxScanWindow = 100

// decodeJSON reads exactly one JSON value from the request body into v. It rejects bodies over
// maxBytes with 413, and empty bodies, unknown fields, malformed JSON, and trailing data with 400.
// On failure the response is already written, so the caller only returns.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if extra := dec.Decode(&struct{}{}); !errors.Is(extra, io.EOF) {
			err = errors.Join(fmt.Errorf("%w: data after the JSON value", ErrBadRequest), extra)
		}
	}
	if err == nil {
		return nil
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit))
	case errors.Is(err, io.EOF):
		writeError(w, http.StatusBadRequest, "request body required")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		writeError(w, http.StatusBadRequest,
			"invalid JSON body: unknown field "+strings.TrimPrefix(err.Error(), "json: unknown field "))
	default:
		writeError(w, http.StatusBadRequest, "invalid JSON body")
	}
	return err
}

// queryLimit returns the positive integer query parameter key, def when it is absent or not a
// positive integer, and ceiling when it is larger than ceiling.
func queryLimit(r *http.Request, key string, def, ceiling int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, ceiling)
}

// writeStoreError answers a failed store call: 404 with notFound when the record does not
// exist, otherwise a logged 500 naming the operation.
func (s *Server) writeStoreError(w http.ResponseWriter, err error, op, notFound string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, notFound)
		return
	}
	s.log.Error(op, zap.Error(err))
	writeError(w, http.StatusInternalServerError, op+" failed")
}

// latestScan returns the scan a read endpoint reports on: the one named by the request's ?scan=
// parameter, else the newest stored scan. A named scan that does not exist writes a 404 and a
// store error writes a 500, both returning ok=false. When no scan exists at all it returns a nil
// record with ok=true so the caller can choose its demo fallback or 404.
func (s *Server) latestScan(w http.ResponseWriter, r *http.Request, op string) (*store.ScanRecord, bool) {
	if id := r.URL.Query().Get("scan"); id != "" {
		rec, err := s.store.GetScan(r.Context(), id)
		if err != nil {
			s.writeStoreError(w, err, op, "scan not found")
			return nil, false
		}
		return rec, true
	}
	scans, err := s.store.ListScans(r.Context(), 1)
	if err != nil {
		s.writeStoreError(w, err, op, "no scans available")
		return nil, false
	}
	if len(scans) == 0 {
		return nil, true
	}
	return &scans[0], true
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
	limit := queryLimit(r, "limit", 50, maxScanWindow)
	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.log.Error("list scans", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// handleGetScan returns a scan record by ID.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "get scan", "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// handleGetScanReport rebuilds and returns the full report for a scan.
func (s *Server) handleGetScanReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	scan, err := s.store.GetScan(ctx, id)
	if err != nil {
		s.writeStoreError(w, err, "get scan", "scan not found")
		return
	}

	results, err := s.store.GetScanResults(ctx, id)
	if err != nil {
		s.log.Error("get scan results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	rpt := s.buildReport(ctx, *scan, results)

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

	s.markAcked(ctx, rpt.Findings)
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
// context. The scan ID is allocated before the scan starts and returned
// immediately, so a client can poll GET /api/scans/{id} until it resolves.
// Concurrent triggers receive 429.
func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	var req triggerScanRequest
	if err := decodeJSON(w, r, &req, maxJSONBody); err != nil {
		return
	}

	contexts, err := s.resolveContexts(r.Context(), req)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, safeMessage(err, "group not found"))
			return
		}
		s.log.Error("trigger scan: resolve contexts", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "resolve contexts failed")
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

	scanID, ok := s.startBackgroundScan(scanSourceTriggered, contexts)
	if !ok {
		writeError(w, http.StatusTooManyRequests, "scan in progress; retry later")
		return
	}
	writeJSON(w, http.StatusAccepted, triggerScanResponse{ScanID: scanID, Status: "running"})
}

// startBackgroundScan claims the trigger slot and runs one scan of contexts in the background
// under the server context, tracked by s.bg so Close waits for it. It returns the ID the scan
// will be saved under, or ok=false when another triggered scan still holds the slot.
func (s *Server) startBackgroundScan(source string, contexts []string) (scanID string, ok bool) {
	if !s.scanBusy.CompareAndSwap(false, true) {
		return "", false
	}
	scanID = store.NewScanID()
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer s.scanBusy.Store(false)
		_, _, _ = s.executeScan(s.ctx, scanRequest{
			Source: source, ScanID: scanID, Contexts: contexts, Emit: emitAll,
		})
	}()
	return scanID, true
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
	tags, err := s.store.ListClusterTags(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "list cluster tags", "cluster tags not found")
		return
	}
	for i := range clusters {
		if t, ok := tags[clusters[i].Name]; ok {
			clusters[i].Tags = t
		}
	}
	writeJSON(w, http.StatusOK, clusters)
}

// handleGetClusterDetail returns full scanner data for a cluster from the
// latest scan, plus its health summary and relevant findings.
func (s *Server) handleGetClusterDetail(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	ctx := r.Context()

	latest, ok := s.latestScan(w, r, "cluster detail: list scans")
	if !ok {
		return
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	in, ok := s.scanInputFor(w, r, *latest, "cluster detail")
	if !ok {
		return
	}
	clusterData, ok := in.Results[cluster]
	if !ok {
		writeError(w, http.StatusNotFound, "cluster not found in latest scan")
		return
	}

	rpt := in.build()

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
	s.markAcked(ctx, clusterFindings)
	peers, dists := clusterPlacement(rpt, cluster)

	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":       cluster,
		"scan_id":       latest.ID,
		"scan_time":     latest.Timestamp,
		"health":        clusterHealth,
		"findings":      clusterFindings,
		"scanner_data":  scannerData,
		"peers":         peers,
		"distributions": dists,
	})
}

// clusterPlacement returns where cluster sits in the fleet: its nearest peers on the cohort map
// and every distribution, in any scope, that flags it.
func clusterPlacement(rpt *report.Report, cluster string) ([]cohort.Peer, []report.Distribution) {
	peers := []cohort.Peer{}
	for _, p := range report.CohortMapFor(rpt).Points {
		if p.Cluster == cluster && p.Peers != nil {
			peers = p.Peers
		}
	}
	dists := []report.Distribution{}
	for _, d := range rpt.Distributions {
		for _, v := range d.Values {
			if v.Cluster == cluster && v.Outlier {
				dists = append(dists, d)
				break
			}
		}
	}
	return peers, dists
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

// handleCreateGroup creates or replaces a group. Only an actor that can manage groups may call
// it, because a group-scoped key gains whatever clusters its group lists.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !actorFromContext(r.Context()).CanManageGroups() {
		writeError(w, http.StatusForbidden, "admin role or wildcard scope required")
		return
	}
	var req createGroupRequest
	if err := decodeJSON(w, r, &req, maxJSONBody); err != nil {
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

// handleDeleteGroup deletes a group. It carries the same scope requirement as
// handleCreateGroup, since deleting a group revokes every key scoped to it.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !actorFromContext(r.Context()).CanManageGroups() {
		writeError(w, http.StatusForbidden, "admin role or wildcard scope required")
		return
	}
	name := r.PathValue("name")
	if err := s.store.DeleteGroup(r.Context(), name); err != nil {
		s.writeStoreError(w, err, "delete group", "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetTrends returns fleet-wide trend analysis from the last N scans.
func (s *Server) handleGetTrends(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r, "scans", 10, maxScanWindow)
	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.log.Error("list scans for trends", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list scans failed")
		return
	}
	if len(scans) < 2 {
		writeJSON(w, http.StatusOK, map[string]string{"message": "need at least 2 scans for trends"})
		return
	}

	scanMetas := make([]report.ScanMeta, len(scans))
	fleetResults := make(map[string]map[string]map[string]any, len(scans))

	for i, scan := range scans {
		scanMetas[i] = report.ScanMeta{ID: scan.ID, Timestamp: scan.Timestamp}
		raw, err := s.store.GetScanResults(r.Context(), scan.ID)
		if err != nil {
			s.writeStoreError(w, err, "trends: get scan results", "scan results not found")
			return
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
	s.markAcked(r.Context(), findings)
	writeJSON(w, http.StatusOK, map[string]any{
		"fleet_trends": trends,
		"findings":     findings,
	})
}

// handleGetClusterTrends returns trends for a specific cluster.
func (s *Server) handleGetClusterTrends(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	limit := queryLimit(r, "scans", 10, maxScanWindow)
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
			s.writeStoreError(w, err, "cluster trends: get scan results", "scan results not found")
			return
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
	selfDrift := report.DetectSelfDrift(cluster, scanMetas, clusterResults)
	findings := report.GenerateTrendFindings(trends, nil)
	findings = append(findings, report.SelfDriftFindings(selfDrift)...)
	s.markAcked(r.Context(), findings)
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":        cluster,
		"cluster_trends": trends,
		"self_drift":     selfDrift,
		"findings":       findings,
	})
}

// handleGetOutliers runs outlier detection on the most recent scan.
func (s *Server) handleGetOutliers(w http.ResponseWriter, r *http.Request) {
	latest, ok := s.latestScan(w, r, "outliers: list scans")
	if !ok {
		return
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

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

	opts := s.reportOptions(r.Context(), s.log)
	opts.Timestamp, opts.OutlierThreshold = latest.Timestamp, threshold
	rpt := report.Build(latest.Clusters, results, opts)
	s.markAcked(r.Context(), rpt.Findings)
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":  latest.ID,
		"outliers": rpt.Outliers,
		"findings": rpt.Findings,
	})
}

// handleGetCohorts returns the cohort partitioning of the most recent scan.
// Cohorts are derived from user-supplied cluster tags first, then from
// agglomerative clustering on scanner-derived features. Each cohort includes
// the outliers that show up within its own baseline, which is the signal that
// the fleet-level view washes out.
func (s *Server) handleGetCohorts(w http.ResponseWriter, r *http.Request) {
	latest, ok := s.latestScan(w, r, "cohorts: list scans")
	if !ok {
		return
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	results, err := s.store.GetScanResults(r.Context(), latest.ID)
	if err != nil {
		s.log.Error("cohorts: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	tags, err := projectCohortTags(r.Context(), s, cohortTagKey)
	if err != nil {
		s.writeStoreError(w, err, "cohorts: list tags", "cluster tags not found")
		return
	}

	threshold := 3.5
	if v := r.URL.Query().Get("threshold"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			threshold = f
		}
	}

	rpt := report.Build(latest.Clusters, results, report.BuildOptions{
		OutlierThreshold: threshold,
		ClusterTags:      tags,
		Timestamp:        latest.Timestamp,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": latest.ID,
		"cohorts": rpt.Cohorts,
	})
}

// cohortTagKey is the cluster-tag key used to carry a cohort label.
const cohortTagKey = "cohort"

// projectCohortTags pulls every cluster's value for the given tag key from the
// store. A store error is returned rather than hidden, because silently falling
// back to automatic cohorts would answer with a different partition.
func projectCohortTags(ctx context.Context, s *Server, key string) (map[string]string, error) {
	all, err := s.store.ListClusterTags(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(all))
	for cluster, kv := range all {
		if v, ok := kv[key]; ok && v != "" {
			out[cluster] = v
		}
	}
	return out, nil
}

// handleGetCapacity returns capacity analysis with correlated signals.
func (s *Server) handleGetCapacity(w http.ResponseWriter, r *http.Request) {
	latest, ok := s.latestScan(w, r, "capacity: list scans")
	if !ok {
		return
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}

	results, err := s.store.GetScanResults(r.Context(), latest.ID)
	if err != nil {
		s.log.Error("capacity: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "capacity: list groups", "groups not found")
		return
	}
	groupMap := make(map[string][]string, len(groups))
	for _, g := range groups {
		groupMap[g.Name] = g.Clusters
	}

	rpt := report.Build(latest.Clusters, results, report.BuildOptions{Groups: groupMap, Timestamp: latest.Timestamp})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":  latest.ID,
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
// without leaving the dashboard. The demo never reaches real clusters, so in
// demo mode the list is empty and nothing can be added to the seeded fleet.
func (s *Server) handleListContexts(w http.ResponseWriter, r *http.Request) {
	if s.demo {
		writeJSON(w, http.StatusOK, []contextInfo{})
		return
	}
	contexts, err := kube.AvailableContexts(s.kubeconfigPath)
	if err != nil {
		s.log.Warn("list contexts", zap.Error(err))
		writeJSON(w, http.StatusOK, []contextInfo{})
		return
	}
	known, err := s.store.ListClusters(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "list contexts: list clusters", "clusters not found")
		return
	}
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
