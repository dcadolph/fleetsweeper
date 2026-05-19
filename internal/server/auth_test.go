package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

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
