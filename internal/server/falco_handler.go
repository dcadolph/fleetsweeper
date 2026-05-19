package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// falcoEvent mirrors the JSON envelope Falco's HTTP_OUTPUT emits. Only
// the fields Fleetsweeper consumes are decoded; unknown fields are
// preserved verbatim in the persisted labels/annotations maps.
type falcoEvent struct {
	// Output is the rendered Falco message.
	Output string `json:"output"`
	// Priority is one of Emergency/Alert/Critical/Error/Warning/Notice/Informational/Debug.
	Priority string `json:"priority"`
	// Rule is the Falco rule name that fired.
	Rule string `json:"rule"`
	// Time is the event time (RFC3339Nano in Falco's format).
	Time time.Time `json:"time"`
	// OutputFields carries the structured key/value pairs Falco resolved
	// for the rule (k8s.pod.name, container.id, fd.name, ...). Fleetsweeper
	// stores these as the alert's labels.
	OutputFields map[string]any `json:"output_fields"`
	// Hostname is the node where the event was observed.
	Hostname string `json:"hostname"`
	// Source is the Falco event source ("syscall", "k8s_audit", ...).
	Source string `json:"source"`
	// Tags is the list of Falco rule tags.
	Tags []string `json:"tags"`
}

// clusterHeader is the HTTP header callers set to associate a Falco
// event with a Fleetsweeper-known cluster when the event payload itself
// doesn't carry a `cluster` or `k8s_cluster_name` field. Common for
// falcosidekick deployments that haven't been configured with
// customfields.
const clusterHeader = "X-Fleetsweeper-Cluster"

// handleFalcoWebhook accepts a Falco HTTP_OUTPUT event and persists it
// to the alerts table tagged with source=falco. Authentication reuses
// the shared --webhook-secret as a bearer token so the falcosidekick
// http_config maps directly. Disabled (404) when no secret is set.
func (s *Server) handleFalcoWebhook(w http.ResponseWriter, r *http.Request) {
	if s.webhookSecret == "" {
		writeError(w, http.StatusNotFound, "falco webhook disabled")
		return
	}
	if !verifyBearer(r.Header.Get("Authorization"), s.webhookSecret) {
		s.log.Warn("falco webhook: bearer rejected")
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body too large or unreadable")
		return
	}
	var ev falcoEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if ev.Rule == "" {
		writeError(w, http.StatusBadRequest, "missing rule field")
		return
	}

	rec := buildFalcoAlert(ev, r.Header.Get(clusterHeader), time.Now().UTC())
	if err := s.store.UpsertAlert(r.Context(), rec); err != nil {
		s.log.Warn("falco webhook: upsert failed",
			zap.String("fingerprint", rec.Fingerprint),
			zap.Error(err))
		writeError(w, http.StatusInternalServerError, "store failure")
		return
	}
	s.alertsReceivedFalco.Add(1)
	s.PublishEvent(EventAlertReceived, alertEventPayload{
		Fingerprint: rec.Fingerprint,
		Cluster:     rec.Cluster,
		Status:      rec.Status,
		AlertName:   rec.AlertName,
		Severity:    rec.Severity,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"fingerprint": rec.Fingerprint,
		"cluster":     rec.Cluster,
		"source":      "falco",
	})
}

// buildFalcoAlert turns a Falco event into an AlertRecord. The
// fingerprint is the SHA-256 of (cluster|rule|pod|container) so the
// same Falco rule firing repeatedly on the same workload upserts in
// place rather than producing one row per event.
func buildFalcoAlert(ev falcoEvent, clusterFromHeader string, now time.Time) store.AlertRecord {
	labels := stringifyFalcoFields(ev.OutputFields)
	labels["source"] = "falco"
	if len(ev.Tags) > 0 {
		labels["tags"] = strings.Join(ev.Tags, ",")
	}
	if ev.Source != "" {
		labels["falco_source"] = ev.Source
	}
	if ev.Hostname != "" {
		labels["hostname"] = ev.Hostname
	}

	cluster := firstNonEmpty(
		labels["cluster"],
		labels["k8s_cluster_name"],
		labels["k8s.cluster.name"],
		clusterFromHeader,
	)
	if cluster != "" {
		labels["cluster"] = cluster
	}

	pod := firstNonEmpty(labels["k8s.pod.name"], labels["k8s_pod_name"])
	container := firstNonEmpty(labels["container.id"], labels["container_id"])
	startsAt := ev.Time
	if startsAt.IsZero() {
		startsAt = now
	}

	return store.AlertRecord{
		Fingerprint: falcoFingerprint(cluster, ev.Rule, pod, container),
		Cluster:     cluster,
		Status:      "firing",
		AlertName:   ev.Rule,
		Severity:    strings.ToLower(ev.Priority),
		Summary:     truncate(ev.Output, 512),
		StartsAt:    startsAt,
		ReceivedAt:  now,
		Labels:      labels,
		Annotations: map[string]string{
			"output": ev.Output,
		},
	}
}

// falcoFingerprint deterministically identifies a Falco alert by the
// tuple that should fold repeated firings onto a single row.
func falcoFingerprint(cluster, rule, pod, container string) string {
	h := sha256.New()
	h.Write([]byte(cluster))
	h.Write([]byte{0})
	h.Write([]byte(rule))
	h.Write([]byte{0})
	h.Write([]byte(pod))
	h.Write([]byte{0})
	h.Write([]byte(container))
	return "falco-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// stringifyFalcoFields coerces Falco's mixed-type output_fields map
// into the string→string shape the alerts table accepts. Non-string
// values are JSON-stringified so structured fields survive the
// round-trip without dropping information.
func stringifyFalcoFields(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string:
			out[k] = t
		case nil:
			continue
		default:
			b, err := json.Marshal(t)
			if err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}
