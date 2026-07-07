package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestHandleListAcks_ReturnsStored verifies active acks are listed.
func TestHandleListAcks_ReturnsStored(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SaveAck(context.Background(), store.AckRecord{
		Fingerprint: "fp-1", Cluster: "east", Scanner: "version",
		Title: "old k8s", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/acks", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "fp-1") {
		t.Errorf("expected seeded ack in body: %s", w.Body.String())
	}
}

// TestHandleCreateAck_Happy verifies a valid ack is persisted with the
// fingerprint taken from the path.
func TestHandleCreateAck_Happy(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	body := `{"cluster":"east","scanner":"version","title":"old","ack_by":"op","reason":"known"}`
	req := httptest.NewRequest(http.MethodPost, "/api/findings/fp-xyz/ack",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	acks, err := ss.ListAcks(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(acks) != 1 || acks[0].Fingerprint != "fp-xyz" || acks[0].AckBy != "op" {
		t.Errorf("unexpected acks: %+v", acks)
	}
}

// TestHandleCreateAck_SnoozeRoundTrip verifies a valid RFC3339 snooze is
// stored on the record.
func TestHandleCreateAck_SnoozeRoundTrip(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	snooze := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	body := `{"cluster":"east","title":"t","snooze_until":"` + snooze + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/findings/fp-snooze/ack",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	acks, _ := ss.ListAcks(context.Background())
	if len(acks) != 1 || acks[0].SnoozeUntil.IsZero() {
		t.Errorf("snooze not stored: %+v", acks)
	}
}

// TestHandleCreateAck_Validation covers the ack-create 400/403 branches.
func TestHandleCreateAck_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name        string
		Fingerprint string
		Body        string
		Actor       *Actor
		WantStatus  int
	}{{ // Test 0: Empty fingerprint.
		Name: "empty fp", Fingerprint: "", Body: `{}`, Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 1: Malformed JSON.
		Name: "bad json", Fingerprint: "fp", Body: "{", Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 2: Cluster outside actor scope.
		Name: "scope reject", Fingerprint: "fp", Body: `{"cluster":"east"}`,
		Actor:      &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}},
		WantStatus: http.StatusForbidden,
	}, { // Test 3: Malformed snooze timestamp.
		Name: "bad snooze", Fingerprint: "fp", Body: `{"cluster":"fleet","snooze_until":"nope"}`,
		Actor:      adminActor(),
		WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPost,
				"/api/findings/"+test.Fingerprint+"/ack",
				strings.NewReader(test.Body))
			req.SetPathValue("fingerprint", test.Fingerprint)
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleCreateAck(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleDeleteAck covers the idempotent delete happy path and the
// empty-fingerprint 400.
func TestHandleDeleteAck(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SaveAck(context.Background(), store.AckRecord{
		Fingerprint: "fp-del", Cluster: "east", Title: "t", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/findings/fp-del/ack", nil)
	dw := httptest.NewRecorder()
	srv.mux.ServeHTTP(dw, del)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", dw.Code)
	}
	acks, _ := ss.ListAcks(context.Background())
	if len(acks) != 0 {
		t.Errorf("expected empty after delete, got %+v", acks)
	}

	empty := httptest.NewRequest(http.MethodDelete, "/api/findings//ack", nil)
	empty.SetPathValue("fingerprint", "")
	ew := httptest.NewRecorder()
	srv.handleDeleteAck(ew, empty)
	if ew.Code != http.StatusBadRequest {
		t.Errorf("empty fp: want 400, got %d", ew.Code)
	}
}
