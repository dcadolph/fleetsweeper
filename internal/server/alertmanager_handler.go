package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// alertManagerPayload mirrors the AlertManager webhook v4 envelope.
// Only the fields Fleetsweeper consumes are decoded; AlertManager
// retains forward-compatibility for fields we ignore.
type alertManagerPayload struct {
	// Version is the AlertManager webhook payload version. Required to be "4".
	Version string `json:"version"`
	// Status is "firing" or "resolved" for the group as a whole.
	Status string `json:"status"`
	// Receiver is the AlertManager receiver name that fired.
	Receiver string `json:"receiver"`
	// GroupLabels are the labels common to every alert in this notification.
	GroupLabels map[string]string `json:"groupLabels"`
	// CommonLabels are the labels common to every alert in this notification.
	CommonLabels map[string]string `json:"commonLabels"`
	// CommonAnnotations are the annotations common to every alert.
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	// ExternalURL is the AlertManager UI URL the alert can be browsed at.
	ExternalURL string `json:"externalURL"`
	// Alerts is the list of individual alerts in this notification.
	Alerts []alertManagerAlert `json:"alerts"`
}

// alertManagerAlert is one alert inside the webhook envelope.
type alertManagerAlert struct {
	// Status is "firing" or "resolved" for this individual alert.
	Status string `json:"status"`
	// Labels are the alert's labels (alertname, severity, cluster, ...).
	Labels map[string]string `json:"labels"`
	// Annotations are the alert's annotations (summary, description, ...).
	Annotations map[string]string `json:"annotations"`
	// StartsAt is when the alert began firing.
	StartsAt time.Time `json:"startsAt"`
	// EndsAt is when the alert resolved. Zero or far future while firing.
	EndsAt time.Time `json:"endsAt"`
	// GeneratorURL is the Prometheus rule link.
	GeneratorURL string `json:"generatorURL"`
	// Fingerprint is AlertManager's stable identifier for the alert.
	Fingerprint string `json:"fingerprint"`
}

// handleAlertManagerWebhook accepts an AlertManager v4 webhook payload and
// persists every alert in the alerts table. Authentication uses the shared
// --webhook-secret as a bearer token so AlertManager's bearer_token
// http_config option drops in directly. Disabled (404) when no secret is
// configured.
func (s *Server) handleAlertManagerWebhook(w http.ResponseWriter, r *http.Request) {
	if s.webhookSecret == "" {
		writeError(w, http.StatusNotFound, "alertmanager webhook disabled")
		return
	}
	if !verifyBearer(r.Header.Get("Authorization"), s.webhookSecret) {
		s.log.Warn("alertmanager webhook: bearer rejected")
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body too large or unreadable")
		return
	}
	var payload alertManagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if payload.Version != "" && payload.Version != "4" {
		writeError(w, http.StatusBadRequest, "unsupported webhook payload version; want 4")
		return
	}

	now := time.Now().UTC()
	stored := 0
	for _, a := range payload.Alerts {
		rec := buildAlertRecord(a, payload.CommonLabels, payload.CommonAnnotations, now)
		if err := s.store.UpsertAlert(r.Context(), rec); err != nil {
			s.log.Warn("alertmanager webhook: upsert failed",
				zap.String("fingerprint", rec.Fingerprint),
				zap.Error(err))
			continue
		}
		stored++
		s.alertsReceivedAM.Add(1)
		s.PublishEvent(EventAlertReceived, alertEventPayload{
			Fingerprint: rec.Fingerprint,
			Cluster:     rec.Cluster,
			Status:      rec.Status,
			AlertName:   rec.AlertName,
			Severity:    rec.Severity,
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"received": len(payload.Alerts),
		"stored":   stored,
		"receiver": payload.Receiver,
		"status":   payload.Status,
	})
}

// alertEventPayload is the minimal alert summary emitted on the SSE bus.
// Full record details remain queryable via GET /alerts.
type alertEventPayload struct {
	// Fingerprint is the alert's stable identity.
	Fingerprint string `json:"fingerprint"`
	// Cluster is the cluster label value (or empty when AlertManager
	// didn't tag the alert with a cluster).
	Cluster string `json:"cluster"`
	// Status is "firing" or "resolved".
	Status string `json:"status"`
	// AlertName is the alertname label.
	AlertName string `json:"alertname"`
	// Severity is the severity label.
	Severity string `json:"severity,omitempty"`
}

// buildAlertRecord folds an AlertManager alert plus the envelope-level
// common labels/annotations into the row we persist. Per-alert labels
// take precedence over common labels so the most specific value wins.
func buildAlertRecord(a alertManagerAlert, commonLabels, commonAnn map[string]string, now time.Time) store.AlertRecord {
	labels := mergeStringMaps(commonLabels, a.Labels)
	ann := mergeStringMaps(commonAnn, a.Annotations)
	return store.AlertRecord{
		Fingerprint:  a.Fingerprint,
		Cluster:      labels["cluster"],
		Status:       firstNonEmpty(a.Status, "firing"),
		AlertName:    labels["alertname"],
		Severity:     labels["severity"],
		Summary:      ann["summary"],
		StartsAt:     a.StartsAt,
		EndsAt:       a.EndsAt,
		ReceivedAt:   now,
		Labels:       labels,
		Annotations:  ann,
		GeneratorURL: a.GeneratorURL,
	}
}

// mergeStringMaps returns a new map with overlay's keys winning over base.
func mergeStringMaps(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// firstNonEmpty returns the first non-empty input.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// verifyBearer returns true when the Authorization header carries a
// bearer token equal to want, compared in constant time. The compare
// rejects empty wants so a misconfigured server can't accidentally
// authenticate an unauthenticated caller.
func verifyBearer(header, want string) bool {
	if want == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimPrefix(header, prefix)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// handleListAlerts serves GET /alerts with optional filters. Read access
// is gated by the existing auth middleware (role: viewer or higher).
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := store.AlertListOptions{
		Cluster:  q.Get("cluster"),
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := parsePositiveInt(v, 1000); err == nil {
			opts.Limit = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.Since = t
		}
	}

	alerts, err := s.store.ListAlerts(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list alerts: "+err.Error())
		return
	}

	if a, ok := r.Context().Value(actorCtxKey{}).(*Actor); ok && a != nil {
		alerts = filterAlertsByActor(alerts, a, s.groupLookup(r.Context()))
	}

	if len(r.URL.Query()["tag"]) > 0 {
		tagAllows, err := s.parseTagFilter(r.Context(), r)
		if err == nil {
			out := alerts[:0]
			for _, al := range alerts {
				if al.Cluster == "" || tagAllows(al.Cluster) {
					out = append(out, al)
				}
			}
			alerts = out
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// filterAlertsByActor drops alerts whose cluster the actor lacks scope
// for. Alerts with an empty cluster label pass through to admins/operators
// but not viewers — a runtime signal nobody tagged with a cluster is a
// fleet-wide concern, not a per-tenant one.
func filterAlertsByActor(in []store.AlertRecord, a *Actor, groupLookup func(string) []string) []store.AlertRecord {
	if a == nil {
		return in
	}
	if a.Role == store.RoleAdmin {
		return in
	}
	out := in[:0]
	for _, r := range in {
		if r.Cluster == "" && a.Role != store.RoleOperator {
			continue
		}
		if r.Cluster != "" && !a.AllowsCluster(r.Cluster, groupLookup) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// parsePositiveInt parses s as an int in [1, max]. Returns an error for
// non-numeric or out-of-range input.
func parsePositiveInt(s string, max int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errInvalidInt
		}
		n = n*10 + int(c-'0')
		if n > max {
			return max, nil
		}
	}
	if n == 0 {
		return 0, errInvalidInt
	}
	return n, nil
}

// errInvalidInt is the sentinel returned by parsePositiveInt for malformed
// or non-positive input.
var errInvalidInt = stringError("not a positive integer")

// stringError is a tiny error type that avoids dragging fmt.Errorf into
// hot parse paths.
type stringError string

// Error implements the error interface.
func (s stringError) Error() string { return string(s) }
