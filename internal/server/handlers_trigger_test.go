package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestHandleTriggerScan_Paths covers the synchronous validation and
// authorization branches of the scan-trigger handler without launching a
// real scan goroutine. The busy case is exercised by pre-setting the
// in-flight flag so CompareAndSwap short-circuits to 429.
func TestHandleTriggerScan_Paths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		Actor      *Actor
		Busy       bool
		WantStatus int
	}{{ // Test 0: Malformed JSON body.
		Name: "bad json", Body: "{", Actor: adminActor(), WantStatus: http.StatusBadRequest,
	}, { // Test 1: Empty context list.
		Name: "no contexts", Body: `{"contexts":[]}`, Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 2: Group that does not exist.
		Name: "unknown group", Body: `{"group":"ghost"}`, Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 3: Requested contexts all outside actor scope.
		Name: "scope filters all", Body: `{"contexts":["east"]}`,
		Actor:      &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}},
		WantStatus: http.StatusForbidden,
	}, { // Test 4: A scan already in progress yields 429.
		Name: "busy", Body: `{"contexts":["east"]}`, Actor: adminActor(), Busy: true,
		WantStatus: http.StatusTooManyRequests,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			if test.Busy {
				srv.scanBusy.Store(true)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/scans",
				strings.NewReader(test.Body))
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleTriggerScan(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleAdminCreateKey_Validation covers the create-key 400 branches and
// the TTL parsing path.
func TestHandleAdminCreateKey_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		WantStatus int
	}{{ // Test 0: Malformed JSON.
		Name: "bad json", Body: "{", WantStatus: http.StatusBadRequest,
	}, { // Test 1: Missing name.
		Name: "empty name", Body: `{"role":"viewer"}`, WantStatus: http.StatusBadRequest,
	}, { // Test 2: Invalid role.
		Name: "bad role", Body: `{"name":"x","role":"wizard"}`, WantStatus: http.StatusBadRequest,
	}, { // Test 3: Malformed TTL duration.
		Name: "bad ttl", Body: `{"name":"x","role":"viewer","ttl":"forever"}`,
		WantStatus: http.StatusBadRequest,
	}, { // Test 4: Valid request with TTL.
		Name: "valid ttl", Body: `{"name":"ci","role":"operator","ttl":"24h"}`,
		WantStatus: http.StatusCreated,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/keys",
				strings.NewReader(test.Body))
			req = req.WithContext(withActor(req.Context(), adminActor()))
			w := httptest.NewRecorder()
			srv.handleAdminCreateKey(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleListContexts_NonDemo verifies the non-demo path returns 200 with
// a JSON array even when no kubeconfig contexts are reachable.
func TestHandleListContexts_NonDemo(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.kubeconfigPath = "/nonexistent/kubeconfig-for-test"
	req := httptest.NewRequest(http.MethodGet, "/api/contexts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.HasPrefix(strings.TrimSpace(w.Body.String()), "[") {
		t.Errorf("expected JSON array, got %s", w.Body.String())
	}
}

// TestHandleGetCohorts_NoScans verifies the empty-store 404 path.
func TestHandleGetCohorts_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/cohorts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleClusterTimeline_ScopeRejected verifies a scoped actor cannot read
// a timeline for a cluster outside its scope.
func TestHandleClusterTimeline_ScopeRejected(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/clusters/east/timeline", nil)
	req.SetPathValue("name", "east")
	scoped := &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}}
	req = req.WithContext(withActor(req.Context(), scoped))
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}
