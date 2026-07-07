package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestWriteJSON_MarshalError verifies an unmarshalable value produces a 500
// rather than a partial body.
func TestWriteJSON_MarshalError(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, make(chan int))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500 on marshal failure, got %d", w.Code)
	}
}

// TestActorFromContext_Fallback verifies a context without an actor yields the
// deny-all default rather than nil.
func TestActorFromContext_Fallback(t *testing.T) {
	t.Parallel()
	a := actorFromContext(context.Background())
	if a == nil || a.ID != "unknown" || a.Role != store.RoleViewer {
		t.Errorf("expected deny-all default, got %+v", a)
	}
}

// TestHandleDeleteGroup_NotFound verifies deleting an unknown group 404s.
func TestHandleDeleteGroup_NotFound(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/groups/ghost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleSetClusterTag_Validation covers the empty-key and malformed-body
// branches.
func TestHandleSetClusterTag_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Key        string
		Body       string
		WantStatus int
	}{{ // Test 0: Empty key rejected before any store write.
		Name: "empty key", Key: "", Body: `{"value":"v"}`, WantStatus: http.StatusBadRequest,
	}, { // Test 1: Malformed JSON body.
		Name: "bad json", Key: "env", Body: "{", WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPut,
				"/api/clusters/east/tags/"+test.Key, strings.NewReader(test.Body))
			req.SetPathValue("name", "east")
			req.SetPathValue("key", test.Key)
			req = req.WithContext(withActor(req.Context(), adminActor()))
			w := httptest.NewRecorder()
			srv.handleSetClusterTag(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d", test.WantStatus, w.Code)
			}
		})
	}
}

// TestHandleDeleteClusterTag_EmptyKey verifies the missing-key 400 branch.
func TestHandleDeleteClusterTag_EmptyKey(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/east/tags/", nil)
	req.SetPathValue("name", "east")
	req.SetPathValue("key", "")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleDeleteClusterTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// TestHandleAckAlert_Branches covers the scope-rejection and malformed-body
// paths against a seeded alert.
func TestHandleAckAlert_Branches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		Actor      *Actor
		WantStatus int
	}{{ // Test 0: Alert cluster outside actor scope.
		Name: "scope reject", Body: `{}`,
		Actor:      &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"other"}},
		WantStatus: http.StatusForbidden,
	}, { // Test 1: Malformed JSON body with content present.
		Name: "bad json", Body: "{", Actor: adminActor(), WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			seedAlertForAck(t, ss)
			req := httptest.NewRequest(http.MethodPost, "/api/alerts/alert-fp/ack",
				strings.NewReader(test.Body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("fingerprint", "alert-fp")
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleAckAlert(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleListAlerts_AllFilters exercises the status, severity, limit, and
// since query-parameter branches.
func TestHandleListAlerts_AllFilters(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	seed := []store.AlertRecord{
		{Fingerprint: "f1", Cluster: "east", Status: "firing", Severity: "critical",
			AlertName: "A", ReceivedAt: time.Now(), Labels: map[string]string{}, Annotations: map[string]string{}},
		{Fingerprint: "f2", Cluster: "west", Status: "resolved", Severity: "warning",
			AlertName: "B", ReceivedAt: time.Now(), Labels: map[string]string{}, Annotations: map[string]string{}},
	}
	for _, a := range seed {
		if err := ss.UpsertAlert(ctx, a); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	url := "/api/alerts?status=firing&severity=critical&limit=10&since=" + since
	req := httptest.NewRequest(http.MethodGet, url, nil)
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
	if resp.Count != 1 || resp.Alerts[0].Fingerprint != "f1" {
		t.Errorf("expected only the firing critical alert, got %+v", resp)
	}
}

// TestClampScore covers the low, high, and in-range branches of the demo
// score clamp.
func TestClampScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         int
		WantResult int
	}{
		{In: -5, WantResult: 0},    // Test 0: Below range.
		{In: 150, WantResult: 100}, // Test 1: Above range.
		{In: 63, WantResult: 63},   // Test 2: In range.
	}
	for i, test := range tests {
		if got := clampScore(test.In); got != test.WantResult {
			t.Errorf("test %d: clampScore(%d) want %d, got %d", i, test.In, test.WantResult, got)
		}
	}
}
