package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetClusterTag_Upsert verifies the PUT endpoint creates the row
// and overwriting the same key updates rather than duplicating.
func TestSetClusterTag_Upsert(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)

	for _, val := range []string{"prod", "production"} {
		req := httptest.NewRequest(http.MethodPut,
			"/api/clusters/east/tags/env",
			strings.NewReader(`{"value":"`+val+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "east")
		req.SetPathValue("key", "env")
		req = req.WithContext(withActor(req.Context(), adminActor()))
		w := httptest.NewRecorder()
		srv.handleSetClusterTag(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
		}
	}

	tags, err := ss.GetClusterTags(context.Background(), "east")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(tags) != 1 || tags["env"] != "production" {
		t.Errorf("expected one upserted tag, got %+v", tags)
	}
}

// TestDeleteClusterTag_Removes verifies the DELETE endpoint clears the row.
func TestDeleteClusterTag_Removes(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if err := ss.SetClusterTag(ctx, "east", "env", "prod"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete,
		"/api/clusters/east/tags/env", nil)
	req.SetPathValue("name", "east")
	req.SetPathValue("key", "env")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleDeleteClusterTag(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}

	tags, _ := ss.GetClusterTags(ctx, "east")
	if len(tags) != 0 {
		t.Errorf("expected empty tags after delete, got %+v", tags)
	}
}

// TestListClusterTags_PerCluster verifies the GET endpoint returns the
// expected map for one cluster.
func TestListClusterTags_PerCluster(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	for k, v := range map[string]string{"env": "prod", "tier": "critical", "owner": "platform"} {
		if err := ss.SetClusterTag(ctx, "east", k, v); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/east/tags", nil)
	req.SetPathValue("name", "east")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleListClusterTags(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["env"] != "prod" || got["tier"] != "critical" || got["owner"] != "platform" {
		t.Errorf("decoded: %+v", got)
	}
}

// TestListAllTags_GroupsByCluster verifies the fleet-wide GET returns
// the nested map.
func TestListAllTags_GroupsByCluster(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	_ = ss.SetClusterTag(ctx, "east", "env", "prod")
	_ = ss.SetClusterTag(ctx, "west", "env", "prod")
	_ = ss.SetClusterTag(ctx, "west", "tier", "critical")

	req := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleListAllTags(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var got map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["east"]["env"] != "prod" || got["west"]["env"] != "prod" || got["west"]["tier"] != "critical" {
		t.Errorf("decoded: %+v", got)
	}
}

// TestSetClusterTag_RejectsOutOfScopeActor verifies a viewer with a
// limited cluster scope can't write tags on a cluster they don't own.
func TestSetClusterTag_RejectsOutOfScopeActor(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	scoped := &Actor{
		ID: "scoped", Role: "operator",
		ClusterScope: []string{"west"},
	}
	req := httptest.NewRequest(http.MethodPut,
		"/api/clusters/east/tags/env",
		strings.NewReader(`{"value":"prod"}`))
	req.SetPathValue("name", "east")
	req.SetPathValue("key", "env")
	req = req.WithContext(withActor(req.Context(), scoped))
	w := httptest.NewRecorder()
	srv.handleSetClusterTag(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}
