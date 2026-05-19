package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// alertManagerEnvelope is the minimal v4 payload helper for tests.
func alertManagerEnvelope(alerts ...alertManagerAlert) []byte {
	body, _ := json.Marshal(alertManagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts:  alerts,
	})
	return body
}

// TestAlertManagerWebhook_DisabledWhenNoSecret verifies the endpoint
// reports 404 when --webhook-secret is unset so an unsigned endpoint
// cannot be left exposed by accident.
func TestAlertManagerWebhook_DisabledWhenNoSecret(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = ""
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/alertmanager",
		bytes.NewReader([]byte(`{"version":"4"}`)))
	w := httptest.NewRecorder()
	srv.handleAlertManagerWebhook(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 disabled, got %d", w.Code)
	}
}

// TestAlertManagerWebhook_RejectsBadBearer verifies an unsigned or
// mismatched Authorization header is rejected with 401.
func TestAlertManagerWebhook_RejectsBadBearer(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "expected-secret"
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/alertmanager",
		bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	srv.handleAlertManagerWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 bad bearer, got %d", w.Code)
	}
}

// TestAlertManagerWebhook_StoresAlertAndEmitsEvent verifies a valid
// payload is persisted, the SSE bus sees an alert.received event, and the
// response carries the receipt counts.
func TestAlertManagerWebhook_StoresAlertAndEmitsEvent(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	srv.webhookSecret = "topsecret"

	events, unsub := srv.events.subscribe(4)
	defer unsub()

	body := alertManagerEnvelope(alertManagerAlert{
		Status:      "firing",
		Fingerprint: "fp-abc-1",
		StartsAt:    time.Now().Add(-30 * time.Second),
		Labels: map[string]string{
			"alertname": "HighMemory",
			"severity":  "critical",
			"cluster":   "prod-east",
		},
		Annotations: map[string]string{
			"summary": "Memory above 90% on prod-east kube-apiserver",
		},
		GeneratorURL: "https://prom.example/graph?expr=mem",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/alertmanager",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer topsecret")
	w := httptest.NewRecorder()
	srv.handleAlertManagerWebhook(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", w.Code, w.Body.String())
	}
	alerts, err := ss.ListAlerts(context.Background(), store.AlertListOptions{})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert stored, got %d", len(alerts))
	}
	got := alerts[0]
	if got.Cluster != "prod-east" || got.AlertName != "HighMemory" ||
		got.Severity != "critical" || got.Status != "firing" ||
		got.Summary == "" {
		t.Errorf("unexpected alert: %+v", got)
	}

	select {
	case ev := <-events:
		if ev.Type != EventAlertReceived {
			t.Errorf("event type: want %q, got %q", EventAlertReceived, ev.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("expected alert.received event")
	}
}

// TestAlertManagerWebhook_UpsertOnFingerprint verifies that re-posting
// the same fingerprint with a "resolved" status overwrites the row
// rather than creating a duplicate.
func TestAlertManagerWebhook_UpsertOnFingerprint(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	srv.webhookSecret = "topsecret"

	firing := alertManagerEnvelope(alertManagerAlert{
		Status:      "firing",
		Fingerprint: "fp-upsert",
		Labels:      map[string]string{"alertname": "X", "cluster": "c1"},
	})
	resolved := alertManagerEnvelope(alertManagerAlert{
		Status:      "resolved",
		Fingerprint: "fp-upsert",
		EndsAt:      time.Now(),
		Labels:      map[string]string{"alertname": "X", "cluster": "c1"},
	})

	for _, body := range [][]byte{firing, resolved} {
		req := httptest.NewRequest(http.MethodPost, "/api/webhooks/alertmanager",
			bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer topsecret")
		w := httptest.NewRecorder()
		srv.handleAlertManagerWebhook(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", w.Code)
		}
	}

	rows, err := ss.ListAlerts(context.Background(), store.AlertListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("want one row after upsert, got %d", len(rows))
	}
	if rows[0].Status != "resolved" {
		t.Errorf("want status resolved after upsert, got %q", rows[0].Status)
	}
}

// TestAlertManagerWebhook_VersionGate verifies a payload claiming v3 is
// rejected. Empty version is tolerated for tests and tools.
func TestAlertManagerWebhook_VersionGate(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "topsecret"

	body, _ := json.Marshal(alertManagerPayload{Version: "3"})
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/alertmanager",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer topsecret")
	w := httptest.NewRecorder()
	srv.handleAlertManagerWebhook(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for v3 payload, got %d", w.Code)
	}
}

// TestListAlerts_FilterByCluster verifies the cluster query parameter
// restricts the returned set.
func TestListAlerts_FilterByCluster(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	for _, c := range []string{"a", "b", "c"} {
		if err := ss.UpsertAlert(ctx, store.AlertRecord{
			Fingerprint: "fp-" + c, Cluster: c,
			AlertName: "X", Status: "firing", ReceivedAt: time.Now(),
			Labels: map[string]string{"cluster": c}, Annotations: map[string]string{},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/alerts?cluster=b", nil)
	w := httptest.NewRecorder()
	srv.handleListAlerts(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Alerts []store.AlertRecord `json:"alerts"`
		Count  int                 `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || resp.Alerts[0].Cluster != "b" {
		t.Errorf("filter mismatch: %+v", resp)
	}
}

// TestVerifyBearer_ConstantTime sanity-checks the bearer comparator.
func TestVerifyBearer_ConstantTime(t *testing.T) {
	t.Parallel()
	if !verifyBearer("Bearer abc", "abc") {
		t.Error("expected match")
	}
	if verifyBearer("Bearer abc", "abd") {
		t.Error("expected mismatch")
	}
	if verifyBearer("", "abc") {
		t.Error("empty header should fail")
	}
	if verifyBearer("Bearer abc", "") {
		t.Error("empty secret should never authenticate")
	}
}
