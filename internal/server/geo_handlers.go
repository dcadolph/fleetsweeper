package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// geoPoint is the per-cluster record returned by /api/geo. It merges the
// auto-detected location from the geo scanner with any manual override the
// operator has stored, and decorates it with the cluster's current health
// status so the globe can color points without a second request.
type geoPoint struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// Status is healthy, busy, degraded, or critical (drives globe color).
	Status string `json:"status"`
	// Provider is the cloud provider for auto-detected entries.
	Provider string `json:"provider,omitempty"`
	// Region is the cloud region or manual region label.
	Region string `json:"region,omitempty"`
	// City is a human-readable label (cloud city or manual site).
	City string `json:"city,omitempty"`
	// Site is the operator-supplied label for manual overrides.
	Site string `json:"site,omitempty"`
	// Lat is degrees north (positive) or south (negative).
	Lat float64 `json:"lat"`
	// Lng is degrees east (positive) or west (negative).
	Lng float64 `json:"lng"`
	// Source is "manual" when the operator set the location, otherwise "auto".
	Source string `json:"source"`
	// CriticalFindings is the count of critical findings for this cluster.
	CriticalFindings int `json:"critical_findings"`
	// WarningFindings is the count of warning findings for this cluster.
	WarningFindings int `json:"warning_findings"`
}

// handleGetGeo returns the geographic placement of every cluster in the
// latest scan. Manual overrides take precedence over auto-detected regions
// from the geo scanner, and clusters with neither are omitted (the UI shows
// a count of those separately). When the server is in demo mode and no
// real scans exist yet, a synthetic fleet is returned so operators can
// preview the globe.
func (s *Server) handleGetGeo(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context(), 1)
	if err != nil || len(scans) == 0 {
		if s.demo {
			writeJSON(w, http.StatusOK, map[string]any{
				"scan_id":   "demo",
				"timestamp": "",
				"points":    demoPoints(),
				"unlocated": []string{},
				"demo":      true,
			})
			return
		}
		writeError(w, http.StatusNotFound, "no scans available")
		return
	}
	results, err := s.store.GetScanResults(r.Context(), scans[0].ID)
	if err != nil {
		s.log.Error("geo: get results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}

	manual, err := s.store.ListLocations(r.Context())
	if err != nil {
		s.log.Warn("geo: list locations", zap.Error(err))
	}
	manualByCluster := make(map[string]store.LocationRecord, len(manual))
	for _, m := range manual {
		manualByCluster[m.Cluster] = m
	}

	rpt := report.Build(scans[0].Clusters, results)
	statusByCluster := make(map[string]report.ClusterHealth, len(rpt.ClusterHealths))
	for _, h := range rpt.ClusterHealths {
		statusByCluster[h.Name] = h
	}

	points := make([]geoPoint, 0, len(scans[0].Clusters))
	unlocated := []string{}

	for _, cluster := range scans[0].Clusters {
		health := statusByCluster[cluster]
		critical := health.FindingCounts[report.SeverityCritical]
		warning := health.FindingCounts[report.SeverityWarning]
		status := health.Status
		if status == "" {
			status = "healthy"
		}

		if m, ok := manualByCluster[cluster]; ok {
			points = append(points, geoPoint{
				Cluster:          cluster,
				Status:           status,
				Lat:              m.Lat,
				Lng:              m.Lng,
				Site:             m.Site,
				City:             m.Site,
				Source:           "manual",
				CriticalFindings: critical,
				WarningFindings:  warning,
			})
			continue
		}

		auto := extractAutoGeo(results, cluster)
		if auto == nil {
			unlocated = append(unlocated, cluster)
			continue
		}
		points = append(points, geoPoint{
			Cluster:          cluster,
			Status:           status,
			Provider:         auto.Provider,
			Region:           auto.Region,
			City:             auto.City,
			Site:             auto.Site,
			Lat:              auto.Lat,
			Lng:              auto.Lng,
			Source:           auto.Source,
			CriticalFindings: critical,
			WarningFindings:  warning,
		})
	}

	sort.Slice(points, func(i, j int) bool { return points[i].Cluster < points[j].Cluster })
	sort.Strings(unlocated)

	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":   scans[0].ID,
		"timestamp": scans[0].Timestamp,
		"points":    points,
		"unlocated": unlocated,
	})
}

// autoGeo is the subset of the geo scanner's Data we consume here. Decoded
// generically so we don't take a hard dependency on the scanner package.
type autoGeo struct {
	// Provider is the cloud provider name (auto-detected entries only).
	Provider string
	// Region is the cloud region.
	Region string
	// City is the human-readable region label.
	City string
	// Site is the operator-supplied site label when the scanner found one
	// in an in-cluster ConfigMap or namespace annotation.
	Site string
	// Source is "configmap", "annotation", or "auto".
	Source string
	// Lat is the latitude.
	Lat float64
	// Lng is the longitude.
	Lng float64
}

// extractAutoGeo pulls the geo scanner's output for a cluster, returning
// nil when the cluster has no usable location.
func extractAutoGeo(results map[string]map[string]scanner.Result, cluster string) *autoGeo {
	scanners, ok := results[cluster]
	if !ok {
		return nil
	}
	result, ok := scanners["geo"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(result.Data)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	hasLocation, _ := m["has_location"].(bool)
	if !hasLocation {
		return nil
	}
	g := &autoGeo{}
	g.Provider, _ = m["provider"].(string)
	g.Region, _ = m["region"].(string)
	g.City, _ = m["city"].(string)
	g.Site, _ = m["site"].(string)
	g.Source, _ = m["source"].(string)
	if g.Source == "" {
		g.Source = "auto"
	}
	if lat, ok := m["lat"].(float64); ok {
		g.Lat = lat
	}
	if lng, ok := m["lng"].(float64); ok {
		g.Lng = lng
	}
	return g
}

// handleListLocations returns every manual location override.
func (s *Server) handleListLocations(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListLocations(r.Context())
	if err != nil {
		s.log.Error("list locations", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list locations failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// setLocationRequest is the JSON body for PUT /api/locations/{cluster}.
type setLocationRequest struct {
	// Lat is degrees north (-90 to 90).
	Lat float64 `json:"lat"`
	// Lng is degrees east (-180 to 180).
	Lng float64 `json:"lng"`
	// Site is a human-readable label.
	Site string `json:"site,omitempty"`
	// Notes is free-form text.
	Notes string `json:"notes,omitempty"`
}

// handleSetLocation upserts a manual location override.
func (s *Server) handleSetLocation(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	if cluster == "" {
		writeError(w, http.StatusBadRequest, "cluster required")
		return
	}
	var req setLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Lat < -90 || req.Lat > 90 {
		writeError(w, http.StatusBadRequest, "lat must be between -90 and 90")
		return
	}
	if req.Lng < -180 || req.Lng > 180 {
		writeError(w, http.StatusBadRequest, "lng must be between -180 and 180")
		return
	}
	if err := s.store.SetLocation(r.Context(), store.LocationRecord{
		Cluster: cluster,
		Lat:     req.Lat,
		Lng:     req.Lng,
		Site:    req.Site,
		Notes:   req.Notes,
	}); err != nil {
		s.log.Error("set location", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "set location failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"cluster": cluster,
		"message": fmt.Sprintf("saved (%.4f, %.4f)", req.Lat, req.Lng),
	})
}

// handleDeleteLocation removes a manual location override.
func (s *Server) handleDeleteLocation(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	if err := s.store.DeleteLocation(r.Context(), cluster); err != nil {
		writeError(w, http.StatusInternalServerError, "delete location failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
