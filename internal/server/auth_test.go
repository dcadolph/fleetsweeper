package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestActorAllowsCluster covers wildcard, direct, and group-prefix matching.
func TestActorAllowsCluster(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{
		"prod": {"prod-east", "prod-west"},
	}
	lookup := func(name string) []string { return groups[name] }

	tests := []struct {
		Name    string
		Scope   []string
		Cluster string
		Want    bool
	}{{
		Name: "Test 0: Wildcard scope allows anything.", Scope: []string{store.ScopeWildcard}, Cluster: "x", Want: true,
	}, {
		Name: "Test 1: Direct match allowed.", Scope: []string{"prod-east"}, Cluster: "prod-east", Want: true,
	}, {
		Name: "Test 2: Non-matching cluster denied.", Scope: []string{"prod-east"}, Cluster: "prod-west", Want: false,
	}, {
		Name: "Test 3: Group prefix resolves members.", Scope: []string{"group:prod"}, Cluster: "prod-west", Want: true,
	}, {
		Name: "Test 4: Group prefix denies non-members.", Scope: []string{"group:prod"}, Cluster: "staging", Want: false,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			a := &Actor{ClusterScope: test.Scope}
			if got := a.AllowsCluster(test.Cluster, lookup); got != test.Want {
				t.Errorf("test %d: want %v, got %v", i, test.Want, got)
			}
		})
	}
}

// TestActorFilterClusters verifies FilterClusters preserves order and drops
// anything outside scope.
func TestActorFilterClusters(t *testing.T) {
	t.Parallel()
	a := &Actor{ClusterScope: []string{"east", "west"}}
	got := a.FilterClusters([]string{"east", "north", "west", "south"}, nil)
	want := []string{"east", "west"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("want %v, got %v", want, got)
	}
}

// TestAuthMiddlewareAPIKey verifies a stored API key authenticates a mutating
// request as its owning role.
func TestAuthMiddlewareAPIKey(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)

	raw, err := store.GenerateToken()
	if err != nil {
		t.Fatalf("gen token: %v", err)
	}
	rec := store.APIKeyRecord{
		ID:           "key_test_op",
		TokenHash:    store.HashToken(raw),
		Name:         "op",
		Role:         store.RoleOperator,
		ClusterScope: []string{store.ScopeWildcard},
	}
	if err := st.SaveAPIKey(context.Background(), rec); err != nil {
		t.Fatalf("save api key: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"x","clusters":[]}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: want 201, got %d body %s", w.Code, w.Body.String())
	}
}

// TestAuthMiddlewareViewerWriteRejected verifies a viewer role cannot mutate.
func TestAuthMiddlewareViewerWriteRejected(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)

	raw, err := store.GenerateToken()
	if err != nil {
		t.Fatalf("gen token: %v", err)
	}
	rec := store.APIKeyRecord{
		ID:           "key_test_view",
		TokenHash:    store.HashToken(raw),
		Name:         "viewer",
		Role:         store.RoleViewer,
		ClusterScope: []string{store.ScopeWildcard},
	}
	if err := st.SaveAPIKey(context.Background(), rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer write: want 403, got %d", w.Code)
	}
}

// TestAuthMiddlewareAdminEndpointGuard verifies non-admin roles cannot reach
// /admin/* even via GET.
func TestAuthMiddlewareAdminEndpointGuard(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)

	raw, _ := store.GenerateToken()
	rec := store.APIKeyRecord{
		ID:           "key_test_op2",
		TokenHash:    store.HashToken(raw),
		Name:         "op",
		Role:         store.RoleOperator,
		ClusterScope: []string{store.ScopeWildcard},
	}
	if err := st.SaveAPIKey(context.Background(), rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator GET /admin: want 403, got %d", w.Code)
	}
}

// TestAdminCreateAndListKeys exercises the full key lifecycle through the API.
func TestAdminCreateAndListKeys(t *testing.T) {
	t.Parallel()
	srv, _ := newAuthTestServer(t)

	body := `{"name":"ci","role":"operator","cluster_scope":["prod-east","group:prod"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d body %s", w.Code, w.Body.String())
	}
	var created createAPIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if !strings.HasPrefix(created.Token, "fsk_") {
		t.Errorf("token prefix: want fsk_, got %q", created.Token)
	}
	if created.Key.Role != store.RoleOperator {
		t.Errorf("role: want operator, got %q", created.Key.Role)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/admin/keys", nil)
	listReq.Header.Set("Authorization", "Bearer bootstrap-secret")
	lw := httptest.NewRecorder()
	srv.mux.ServeHTTP(lw, listReq)
	if lw.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", lw.Code)
	}
	var keys []store.APIKeyRecord
	if err := json.Unmarshal(lw.Body.Bytes(), &keys); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(keys) != 1 || keys[0].Name != "ci" {
		t.Errorf("unexpected keys: %+v", keys)
	}
	if keys[0].TokenHash != "" {
		t.Error("list response leaks token hash")
	}
}

// TestAuditMiddlewareWrites verifies a successful mutating call produces an
// audit_log entry capturing actor, method, path, and status.
func TestAuditMiddlewareWrites(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/groups",
		strings.NewReader(`{"name":"audited","clusters":["c1"]}`))
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: want 201, got %d", w.Code)
	}

	deadline := time.Now().Add(2 * time.Second)
	var entries []store.AuditEntry
	for time.Now().Before(deadline) {
		var err error
		entries, err = st.ListAuditEntries(context.Background(), store.AuditListOptions{})
		if err == nil && len(entries) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("expected an audit entry, got none")
	}
	if entries[0].Method != "POST" || entries[0].Path != "/groups" {
		t.Errorf("unexpected audit entry: %+v", entries[0])
	}
	if entries[0].ActorID != "bootstrap" {
		t.Errorf("actor id: want bootstrap, got %q", entries[0].ActorID)
	}
}

// newAuthTestServer creates a Server backed by a temp SQLite and a bootstrap
// admin token. Used by tests that exercise the full authentication pipeline.
func newAuthTestServer(t *testing.T) (*Server, *store.SQLite) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := store.NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	srv := New(Config{
		Store:     s,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "bootstrap-secret",
	})
	t.Cleanup(func() {
		srv.Close()
		s.Close()
	})
	return srv, s
}

// saveTestKey stores an API key with the given role and scope and returns its raw bearer token.
func saveTestKey(t *testing.T, st *store.SQLite, id, role string, scope ...string) string {
	t.Helper()
	raw, err := store.GenerateToken()
	if err != nil {
		t.Fatalf("gen token: %v", err)
	}
	rec := store.APIKeyRecord{
		ID:           id,
		TokenHash:    store.HashToken(raw),
		Name:         id,
		Role:         role,
		ClusterScope: scope,
	}
	if err := st.SaveAPIKey(context.Background(), rec); err != nil {
		t.Fatalf("save api key: %v", err)
	}
	return raw
}

// TestGroupWritesRequireFleetScope verifies only an admin or a wildcard-scoped actor may create
// or delete a group, and that a refused write leaves the group untouched.
func TestGroupWritesRequireFleetScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Role             string
		Scope            []string
		WantCreateStatus int
		WantDeleteStatus int
	}{{ // Test 0: A group-scoped operator cannot widen its own group.
		Role: store.RoleOperator, Scope: []string{"group:edge"},
		WantCreateStatus: http.StatusForbidden, WantDeleteStatus: http.StatusForbidden,
	}, { // Test 1: A cluster-scoped operator cannot define groups.
		Role: store.RoleOperator, Scope: []string{"edge-a"},
		WantCreateStatus: http.StatusForbidden, WantDeleteStatus: http.StatusForbidden,
	}, { // Test 2: A wildcard operator may manage groups.
		Role: store.RoleOperator, Scope: []string{store.ScopeWildcard},
		WantCreateStatus: http.StatusCreated, WantDeleteStatus: http.StatusNoContent,
	}, { // Test 3: An admin may manage groups even with a narrow scope.
		Role: store.RoleAdmin, Scope: []string{"group:edge"},
		WantCreateStatus: http.StatusCreated, WantDeleteStatus: http.StatusNoContent,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, st := newAuthTestServer(t)
			ctx := context.Background()
			if err := st.SaveGroup(ctx, "edge", []string{"edge-a"}); err != nil {
				t.Fatalf("seed group: %v", err)
			}
			raw := saveTestKey(t, st, "key_scope", test.Role, test.Scope...)

			body := `{"name":"edge","clusters":["edge-a","core-1","core-2"]}`
			req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+raw)
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != test.WantCreateStatus {
				t.Fatalf("create: want %d, got %d body=%s", test.WantCreateStatus, w.Code, w.Body.String())
			}
			if test.WantCreateStatus == http.StatusForbidden {
				g, err := st.GetGroup(ctx, "edge")
				if err != nil {
					t.Fatalf("get group: %v", err)
				}
				if diff := cmp.Diff([]string{"edge-a"}, g.Clusters); diff != "" {
					t.Errorf("refused create changed the group (-want +got):\n%s", diff)
				}
			}

			req = httptest.NewRequest(http.MethodDelete, "/api/groups/edge", nil)
			req.Header.Set("Authorization", "Bearer "+raw)
			w = httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != test.WantDeleteStatus {
				t.Fatalf("delete: want %d, got %d body=%s", test.WantDeleteStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestCanManageGroups covers the role and scope combinations directly.
func TestCanManageGroups(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Actor      Actor
		WantResult bool
	}{{ // Test 0: Admin with wildcard scope.
		Actor: Actor{Role: store.RoleAdmin, ClusterScope: []string{store.ScopeWildcard}}, WantResult: true,
	}, { // Test 1: Admin with a narrow scope.
		Actor: Actor{Role: store.RoleAdmin, ClusterScope: []string{"east"}}, WantResult: true,
	}, { // Test 2: Operator with wildcard scope.
		Actor: Actor{Role: store.RoleOperator, ClusterScope: []string{"east", store.ScopeWildcard}}, WantResult: true,
	}, { // Test 3: Operator with a group scope.
		Actor: Actor{Role: store.RoleOperator, ClusterScope: []string{"group:prod"}}, WantResult: false,
	}, { // Test 4: Anonymous viewer with no scope.
		Actor: Actor{Role: store.RoleViewer}, WantResult: false,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := test.Actor.CanManageGroups(); got != test.WantResult {
				t.Errorf("want %v, got %v", test.WantResult, got)
			}
		})
	}
}

// touchCountingStore counts TouchAPIKey calls per key.
type touchCountingStore struct {
	store.Store
	// mu guards touches.
	mu sync.Mutex
	// touches maps a key ID to its TouchAPIKey call count.
	touches map[string]int
}

// TouchAPIKey counts the call and delegates to the wrapped store.
func (s *touchCountingStore) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	s.touches[id]++
	s.mu.Unlock()
	return s.Store.TouchAPIKey(ctx, id, at)
}

// TestTouchAPIKeyDebounced verifies a burst of authenticated requests writes the key's
// last-used time once, that a different key is touched independently, and that the write
// happens again once keyTouchInterval has passed.
func TestTouchAPIKeyDebounced(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)
	counter := &touchCountingStore{Store: st, touches: map[string]int{}}
	srv.store = counter
	rawA := saveTestKey(t, st, "key_a", store.RoleViewer, store.ScopeWildcard)
	rawB := saveTestKey(t, st, "key_b", store.RoleViewer, store.ScopeWildcard)

	get := func(raw string) {
		req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", w.Code)
		}
	}
	for range 5 {
		get(rawA)
	}
	get(rawB)
	srv.bg.Wait()
	counter.mu.Lock()
	if diff := cmp.Diff(map[string]int{"key_a": 1, "key_b": 1}, counter.touches); diff != "" {
		t.Errorf("touches mismatch (-want +got):\n%s", diff)
	}
	counter.mu.Unlock()

	srv.keyTouchMu.Lock()
	srv.keyTouches["key_a"] = time.Now().UTC().Add(-keyTouchInterval - time.Second)
	srv.keyTouchMu.Unlock()
	get(rawA)
	srv.bg.Wait()
	counter.mu.Lock()
	defer counter.mu.Unlock()
	if got := counter.touches["key_a"]; got != 2 {
		t.Errorf("after the interval: want 2 touches of key_a, got %d", got)
	}
}

// errGroupLookup is the failure injected by groupStoreMock in lookup tests.
var errGroupLookup = errors.New("group lookup boom")

// groupStoreMock returns configurable values from GetGroup.
type groupStoreMock struct {
	store.Store
	// Group is the record GetGroup returns.
	Group *store.GroupRecord
	// Err is the error GetGroup returns.
	Err error
}

// GetGroup returns the configured record and error.
func (m groupStoreMock) GetGroup(context.Context, string) (*store.GroupRecord, error) {
	return m.Group, m.Err
}

// TestGroupLookup covers found, missing, failed, and nil group lookups.
func TestGroupLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Group           *store.GroupRecord
		Err             error
		WantClusters    []string
		WantErrorLogs   int
		WantAllowsGroup bool
	}{{ // Test 0: Found group returns its clusters.
		Group:        &store.GroupRecord{Clusters: []string{"a", "b"}},
		WantClusters: []string{"a", "b"}, WantAllowsGroup: true,
	}, { // Test 1: ErrNotFound returns nil without an error log.
		Err: store.ErrNotFound,
	}, { // Test 2: Other error returns nil and logs at error level.
		Err: errGroupLookup, WantErrorLogs: 1,
	}, { // Test 3: Nil record returns nil.
		Group: nil,
	}, { // Test 4: Wrapped ErrNotFound returns nil without an error log.
		Err: fmt.Errorf("get: %w", store.ErrNotFound),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			core, logs := observer.New(zapcore.DebugLevel)
			srv := &Server{
				store: groupStoreMock{Group: test.Group, Err: test.Err},
				log:   zap.New(core),
			}
			lookup := srv.groupLookup(context.Background())
			got := lookup("g")
			if diff := cmp.Diff(test.WantClusters, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("clusters mismatch (-want +got):\n%s", diff)
			}
			errLogs := logs.FilterLevelExact(zapcore.ErrorLevel).Len()
			if errLogs != test.WantErrorLogs {
				t.Errorf("error logs = %d, want %d", errLogs, test.WantErrorLogs)
			}
			actor := &Actor{ClusterScope: []string{"group:g"}}
			if allowed := actor.AllowsCluster("a", lookup); allowed != test.WantAllowsGroup {
				t.Errorf("AllowsCluster = %v, want %v", allowed, test.WantAllowsGroup)
			}
		})
	}
}
