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

// falcoEnvelope is a minimal Falco HTTP_OUTPUT payload helper.
func falcoEnvelope(rule, cluster string, fields map[string]any) []byte {
	body, _ := json.Marshal(falcoEvent{
		Output:       "Suspicious file open detected (" + rule + ")",
		Priority:     "Critical",
		Rule:         rule,
		Time:         time.Now().Add(-time.Second),
		OutputFields: fields,
		Hostname:     "node-1",
		Source:       "syscall",
		Tags:         []string{"container", "drift"},
	})
	_ = cluster
	return body
}

// TestFalcoWebhook_DisabledWhenNoSecret confirms a missing secret
// returns 404 rather than silently accepting events.
func TestFalcoWebhook_DisabledWhenNoSecret(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = ""
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
		bytes.NewReader([]byte(`{"rule":"r"}`)))
	w := httptest.NewRecorder()
	srv.handleFalcoWebhook(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 disabled, got %d", w.Code)
	}
}

// TestFalcoWebhook_RejectsBadBearer verifies the bearer comparator
// fires.
func TestFalcoWebhook_RejectsBadBearer(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "expected"
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
		bytes.NewReader([]byte(`{"rule":"r"}`)))
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	srv.handleFalcoWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

// TestFalcoWebhook_StoresEventAndEmitsSSE verifies a valid Falco event
// lands in the alerts table tagged with source=falco and emits an
// alert.received SSE event.
func TestFalcoWebhook_StoresEventAndEmitsSSE(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	srv.webhookSecret = "topsecret"
	events, unsub := srv.events.subscribe(4)
	defer unsub()

	body := falcoEnvelope("Container Drift Detected", "prod-east", map[string]any{
		"k8s.ns.name":   "payments",
		"k8s.pod.name":  "checkout-7",
		"container.id":  "abc123",
		"proc.name":     "sshd",
		"fd.name":       "/etc/passwd",
		"cluster":       "prod-east",
		"unknown_field": 42,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer topsecret")
	w := httptest.NewRecorder()
	srv.handleFalcoWebhook(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", w.Code, w.Body.String())
	}
	alerts, err := ss.ListAlerts(context.Background(), store.AlertListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 stored, got %d", len(alerts))
	}
	got := alerts[0]
	if got.Cluster != "prod-east" {
		t.Errorf("cluster: want prod-east, got %q", got.Cluster)
	}
	if got.AlertName != "Container Drift Detected" {
		t.Errorf("rule: %q", got.AlertName)
	}
	if got.Severity != "critical" {
		t.Errorf("severity: want critical, got %q", got.Severity)
	}
	if got.Labels["source"] != "falco" {
		t.Errorf("expected source=falco label, got %v", got.Labels)
	}
	if got.Labels["unknown_field"] != "42" {
		t.Errorf("non-string output_field should be JSON-stringified, got %v", got.Labels["unknown_field"])
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

// TestFalcoWebhook_DedupesRepeatFirings verifies the same rule firing
// against the same pod/container produces one row, not many.
func TestFalcoWebhook_DedupesRepeatFirings(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	srv.webhookSecret = "topsecret"

	body := falcoEnvelope("RuleX", "c1", map[string]any{
		"k8s.pod.name": "p1",
		"container.id": "ctr1",
		"cluster":      "c1",
	})
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
			bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer topsecret")
		w := httptest.NewRecorder()
		srv.handleFalcoWebhook(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("attempt %d: want 202, got %d", i, w.Code)
		}
	}
	rows, _ := ss.ListAlerts(context.Background(), store.AlertListOptions{})
	if len(rows) != 1 {
		t.Errorf("want 1 row after 3 firings, got %d", len(rows))
	}
}

// TestFalcoWebhook_ClusterFromHeader verifies the X-Fleetsweeper-Cluster
// header populates the cluster column when the event payload doesn't
// include a cluster label.
func TestFalcoWebhook_ClusterFromHeader(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	srv.webhookSecret = "topsecret"
	body := falcoEnvelope("RuleY", "", map[string]any{
		"k8s.pod.name": "p", "container.id": "c",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer topsecret")
	req.Header.Set(clusterHeader, "from-header")
	w := httptest.NewRecorder()
	srv.handleFalcoWebhook(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", w.Code)
	}
	rows, _ := ss.ListAlerts(context.Background(), store.AlertListOptions{})
	if len(rows) != 1 || rows[0].Cluster != "from-header" {
		t.Errorf("expected cluster from header, got %+v", rows)
	}
}

// TestFalcoWebhook_RejectsEmptyRule verifies a body missing the rule
// field is rejected so we don't store unaddressable rows.
func TestFalcoWebhook_RejectsEmptyRule(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "topsecret"
	body, _ := json.Marshal(falcoEvent{Output: "x", Priority: "Critical"})
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer topsecret")
	w := httptest.NewRecorder()
	srv.handleFalcoWebhook(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for empty rule, got %d", w.Code)
	}
}
