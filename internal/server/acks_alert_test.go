package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// adminActor returns an admin Actor with wildcard cluster scope so
// handler-level cluster checks pass in unit tests that don't go
// through the full middleware chain.
func adminActor() *Actor {
	return &Actor{
		ID: "test-admin", Name: "test-admin",
		Role:         store.RoleAdmin,
		ClusterScope: []string{store.ScopeWildcard},
	}
}

// seedAlertForAck writes one Falco-tagged alert against cluster "prod"
// so the alert-ack tests have a row to target.
func seedAlertForAck(t *testing.T, ss *store.SQLite) {
	t.Helper()
	if err := ss.UpsertAlert(context.Background(), store.AlertRecord{
		Fingerprint: "alert-fp",
		Cluster:     "prod",
		Status:      "firing",
		AlertName:   "ContainerDrift",
		Severity:    "critical",
		ReceivedAt:  time.Now(),
		Labels:      map[string]string{"source": "falco"},
		Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestAckAlert_PersistsRecord verifies a valid alert-ack call creates
// a row in finding_acks with fields pulled from the alert row.
func TestAckAlert_PersistsRecord(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedAlertForAck(t, ss)

	body := strings.NewReader(`{"ack_by":"oncall","reason":"investigating"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/alerts/alert-fp/ack", body)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("fingerprint", "alert-fp")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleAckAlert(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	acks, err := ss.ListAcks(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(acks) != 1 {
		t.Fatalf("want 1 ack, got %d", len(acks))
	}
	got := acks[0]
	if got.Fingerprint != "alert-fp" || got.Cluster != "prod" ||
		got.Title != "ContainerDrift" || got.AckBy != "oncall" ||
		got.Reason != "investigating" {
		t.Errorf("unexpected ack: %+v", got)
	}
	if got.Scanner != "alert:falco" {
		t.Errorf("scanner tag should reflect source, got %q", got.Scanner)
	}
}

// TestAckAlert_UnknownFingerprintReturnsNotFound verifies the handler
// 404s when the alert doesn't exist.
func TestAckAlert_UnknownFingerprintReturnsNotFound(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/missing/ack",
		bytes.NewReader([]byte(`{}`)))
	req.SetPathValue("fingerprint", "missing")
	w := httptest.NewRecorder()
	srv.handleAckAlert(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestAckAlert_SnoozeRoundTrip verifies a future snooze timestamp is
// stored and surfaces in the listed ack.
func TestAckAlert_SnoozeRoundTrip(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedAlertForAck(t, ss)
	snoozeTo := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)

	body := strings.NewReader(`{"ack_by":"a","reason":"flaky probe","snooze_until":"` + snoozeTo + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/alert-fp/ack", body)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("fingerprint", "alert-fp")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleAckAlert(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}

	acks, _ := ss.ListAcks(context.Background())
	if len(acks) != 1 {
		t.Fatalf("want 1 ack, got %d", len(acks))
	}
	if acks[0].SnoozeUntil.IsZero() {
		t.Error("expected snooze_until to be set")
	}
}

// TestAckAlert_EmptyFingerprintReturnsBadRequest verifies the handler
// 400s when path value is missing.
func TestAckAlert_EmptyFingerprintReturnsBadRequest(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/alerts//ack",
		bytes.NewReader(nil))
	w := httptest.NewRecorder()
	srv.handleAckAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// TestListAlertsCarriesAck verifies GET /api/alerts marks an alert acked
// once an ack covers it, and unacked again after the ack is deleted.
func TestListAlertsCarriesAck(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedAlertForAck(t, ss)
	h := srv.Handler()
	ackedOf := func() bool {
		t.Helper()
		var out struct {
			Alerts []alertView `json:"alerts"`
		}
		if code := serve(t, h, http.MethodGet, "/api/alerts", "", "", &out); code != http.StatusOK || len(out.Alerts) != 1 {
			t.Fatalf("list: status %d, %d alerts", code, len(out.Alerts))
		}
		return out.Alerts[0].Acked
	}
	tests := []struct {
		Action    func()
		WantAcked bool
	}{{ // Test 0: No ack yet.
		Action: func() {},
	}, { // Test 1: After an ack.
		Action: func() {
			if err := ss.SaveAck(context.Background(), store.AckRecord{Fingerprint: "alert-fp", CreatedAt: time.Now()}); err != nil {
				t.Fatalf("save ack: %v", err)
			}
		},
		WantAcked: true,
	}, { // Test 2: After the ack is deleted.
		Action: func() {
			if err := ss.DeleteAck(context.Background(), "alert-fp"); err != nil {
				t.Fatalf("delete ack: %v", err)
			}
		},
	}}
	for testNum, test := range tests {
		test.Action()
		if got := ackedOf(); got != test.WantAcked {
			t.Errorf("test %d: acked %v, want %v", testNum, got, test.WantAcked)
		}
	}
}
