package server

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// timelineEntry is one row on a cluster's interleaved history. The
// dashboard shows these in reverse-chronological order so the most
// recent activity bubbles to the top, with kind distinguishing scans
// from inbound alerts.
type timelineEntry struct {
	// Kind is "scan", "alert", or "ack".
	Kind string `json:"kind"`
	// At is when the entry was recorded.
	At time.Time `json:"at"`
	// Severity is critical/warning/info for alerts; empty for scans/acks.
	Severity string `json:"severity,omitempty"`
	// Title is the human-readable label of the entry.
	Title string `json:"title"`
	// Detail is short context — finding count for scans, summary for
	// alerts, ack reason for acks.
	Detail string `json:"detail,omitempty"`
	// Ref is the underlying record's identifier (scan ID, alert
	// fingerprint, ack fingerprint) so the UI can deep-link.
	Ref string `json:"ref,omitempty"`
}

// handleClusterTimeline returns an interleaved chronological view of a
// single cluster: its recent scans, the alerts that landed against it,
// and any active acks. Used by the dashboard to answer "what's
// happened with this cluster lately."
func (s *Server) handleClusterTimeline(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("name")
	if cluster == "" {
		writeError(w, http.StatusBadRequest, "cluster name required")
		return
	}
	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		if !a.AllowsCluster(cluster, s.groupLookup(r.Context())) {
			writeError(w, http.StatusForbidden, "cluster outside actor scope")
			return
		}
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := parsePositiveInt(v, 500); err == nil {
			limit = n
		}
	}

	entries, err := s.buildClusterTimeline(r.Context(), cluster, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "timeline: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster": cluster,
		"count":   len(entries),
		"entries": entries,
	})
}

// buildClusterTimeline gathers scans, alerts, and acks for the cluster
// and returns them sorted newest-first, clipped to limit.
func (s *Server) buildClusterTimeline(ctx context.Context, cluster string, limit int) ([]timelineEntry, error) {
	var out []timelineEntry

	// Pull a wider scan window than the caller's limit because most
	// scans cover many clusters; we filter to the ones the requested
	// cluster appears in.
	scans, err := s.store.ListScans(ctx, limit*5)
	if err != nil {
		return nil, err
	}
	scanCount := 0
	for _, sc := range scans {
		if !containsString(sc.Clusters, cluster) {
			continue
		}
		out = append(out, timelineEntry{
			Kind:  "scan",
			At:    sc.Timestamp,
			Title: "Scan persisted",
			Ref:   sc.ID,
		})
		scanCount++
		if scanCount >= limit {
			break
		}
	}

	alerts, err := s.store.ListAlerts(ctx, store.AlertListOptions{
		Cluster: cluster,
		Limit:   limit,
	})
	if err != nil {
		return nil, err
	}
	for _, a := range alerts {
		out = append(out, timelineEntry{
			Kind:     "alert",
			At:       a.ReceivedAt,
			Severity: a.Severity,
			Title:    a.AlertName,
			Detail:   a.Summary,
			Ref:      a.Fingerprint,
		})
	}

	acks, err := s.store.ListAcks(ctx)
	if err == nil {
		for _, a := range acks {
			if a.Cluster != cluster {
				continue
			}
			out = append(out, timelineEntry{
				Kind:   "ack",
				At:     a.CreatedAt,
				Title:  "Finding ack: " + a.Title,
				Detail: a.Reason,
				Ref:    a.Fingerprint,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].At.After(out[j].At)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// containsString reports whether the slice contains s. Local helper so
// this file does not depend on slices.Contains for an older toolchain.
func containsString(in []string, s string) bool {
	return slices.Contains(in, s)
}
